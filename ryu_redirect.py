from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp
from ryu.lib.packet import ether_types
from ryu.lib import mac
import struct
import logging

LOG = logging.getLogger('ryu.app.syn_redirector')


class SynRedirector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SynRedirector, self).__init__(*args, **kwargs)
        # per-switch mac->port table
        self.mac_to_port = {}
        # remember mapping from ip->mac (learned via ARP or IPv4 packets)
        self.ip_to_mac = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install table-miss flow entry to send to controller."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # table-miss: send to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=0,
                                match=match,
                                instructions=inst)
        datapath.send_msg(mod)
        LOG.info("Installed table-miss flow on dp %s", datapath.id)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=5):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,
                                idle_timeout=idle_timeout)
        datapath.send_msg(mod)
        LOG.info("Added flow on dp %s: match=%s idle_timeout=%s", datapath.id, match, idle_timeout)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Main packet-in handler: learning switch + special TCP-SYN redirect logic."""
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # ignore LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # init mac table for this dpid
        self.mac_to_port.setdefault(dpid, {})

        # learn source MAC -> port
        self.mac_to_port[dpid][eth.src] = in_port

        # ARP: learn ip->mac
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.ip_to_mac[arp_pkt.src_ip] = arp_pkt.src_mac
            # simple ARP handling: if we know target MAC -> send out to that port; else flood
            if arp_pkt.dst_ip in self.ip_to_mac:
                dst_mac = self.ip_to_mac[arp_pkt.dst_ip]
                out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]
            data = msg.data
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port,
                                      actions=actions,
                                      data=data)
            datapath.send_msg(out)
            return

        # IPv4 handling
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            self.ip_to_mac[ip_pkt.src] = eth.src

        # TCP handling: detect SYN from client->server1
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt and ip_pkt:
            is_syn = (tcp_pkt.bits & 0x02) != 0
            # We only react to SYN packets (first packet of TCP handshake)
            if is_syn:
                src_ip = ip_pkt.src
                dst_ip = ip_pkt.dst

                # Find MACs and ports for dst (server1) and server2 (if learned)
                dst_mac = self.ip_to_mac.get(dst_ip)
                dst_port = self.mac_to_port[dpid].get(dst_mac) if dst_mac else None

                # Choose server2: assume server2 IP different from dst_ip and we've learned it earlier via ARP/messaging
                # We will find any ip in ip_to_mac that is not dst_ip or src_ip and treat that as server2.
                server2_ip = None
                for ipaddr in self.ip_to_mac:
                    if ipaddr != dst_ip and ipaddr != src_ip:
                        server2_ip = ipaddr
                        break

                if server2_ip:
                    server2_mac = self.ip_to_mac[server2_ip]
                    server2_port = self.mac_to_port[dpid].get(server2_mac, None)

                    if server2_port is not None:
                        LOG.info("SYN from %s -> %s detected. Redirecting to %s", src_ip, dst_ip, server2_ip)

                        # 1) install flow: match client(src) & server1(dst) & tcp -> set dst ip/mac to server2 and output to server2 port
                        match = parser.OFPMatch(eth_type=0x0800,
                                                ip_proto=6,
                                                ipv4_src=src_ip,
                                                ipv4_dst=dst_ip)
                        actions = [
                            # rewrite dst IPv4 to server2_ip
                            parser.OFPActionSetField(ipv4_dst=server2_ip),
                            # rewrite destination MAC
                            parser.OFPActionSetField(eth_dst=server2_mac),
                            # output to server2 port
                            parser.OFPActionOutput(server2_port)
                        ]
                        # idle_timeout 5 seconds as required
                        self.add_flow(datapath, priority=100, match=match, actions=actions, idle_timeout=5)

                        # 2) craft PacketOut from the original packet but with modified dst ip/mac, and send it out to server2 so SYN reaches server2 now.
                        out_actions = [
                            parser.OFPActionSetField(ipv4_dst=server2_ip),
                            parser.OFPActionSetField(eth_dst=server2_mac),
                            parser.OFPActionOutput(server2_port)
                        ]

                        data = msg.data
                        # if buffer_id != NO_BUFFER, controller might not have full packet.data
                        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                            # request packet from switch
                            data = None

                        out = parser.OFPPacketOut(datapath=datapath,
                                                  buffer_id=msg.buffer_id,
                                                  in_port=in_port,
                                                  actions=out_actions,
                                                  data=data)
                        datapath.send_msg(out)
                        return
                    else:
                        LOG.info("Server2 port unknown yet; cannot redirect. Learned ips: %s", self.ip_to_mac)
                else:
                    LOG.info("No candidate server2 IP learned yet; cannot redirect SYN.")
        # Default learning-switch behavior for other packets:
        dst = eth.dst
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            actions = [parser.OFPActionOutput(out_port)]
            # install flow to avoid future packet_in (idle_timeout 5)
            match_fields = {'in_port': in_port, 'eth_dst': dst}
            if ip_pkt:
                # more specific match
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst)
            else:
                match = parser.OFPMatch(**match_fields)

            self.add_flow(datapath, priority=10, match=match, actions=actions, idle_timeout=5)

        else:
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
