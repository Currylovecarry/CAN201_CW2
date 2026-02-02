# ryu_reactive_controller.py
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, icmp
from ryu.ofproto import ofproto_v1_3
from ryu.lib import mac

#ryu控制器实现reactive forwarding和TCP SYN流量处理
class ReactiveController(app_manager.RyuApp):

    # 使用OpenFlow 1.3版本
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):# 初始化为每个交换机 dpid 维护一个 {mac: port} 的学习表，供 _packet_in_handler 学习源 MAC、计算转发端口并安装流表
        super().__init__(*args, **kwargs)
        # dpid -> {mac: port}
        self.mac_to_port = {}#存储MAC地址到端口的映射

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)# 交换机连接时安装table-miss流表项
    def switch_features_handler(self, ev):
        """安装table-miss流表项，将未知流量发送到控制器"""
        datapath = ev.msg.datapath  # 获取交换机数据路径
        ofproto = datapath.ofproto  # 获取OpenFlow协议
        parser = datapath.ofproto_parser  # 获取OpenFlow解析器

        # 安装table-miss流表项
        match = parser.OFPMatch()  # 匹配所有流量
        # 动作为发送到控制器
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
       # 创建并下发 table-miss 流表项（复用 add_flow 封装）
        self.add_flow(datapath=datapath,
                     priority=0,
                     match=match,
                     actions=actions)
        self.logger.info("Installed table-miss flow on dpid=%s", datapath.id)

    def add_flow(self, datapath, priority, match, actions,buffer_id=None,idle_timeout=0):# 添加流表项的函数
        ofproto = datapath.ofproto# 获取OpenFlow协议
        parser = datapath.ofproto_parser# 获取OpenFlow解析器
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]# 指令为应用动作
        if buffer_id:
            if idle_timeout:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                        priority=priority, match=match, idle_timeout=idle_timeout,
                                        instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                        priority=priority, match=match,
                                        instructions=inst)
        else:
            if idle_timeout:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                        match=match, idle_timeout=idle_timeout,
                                        instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                        match=match, instructions=inst)
        datapath.send_msg(mod)# 发送流表修改消息到交换机
    """这是 Ryu 控制器用来处理 Packet-In 事件的回调方法。它在 MAIN_DISPATCHER 阶段被触发，作用如下：  
            1.学习源 MAC 与入端口映射（构建 mac_to_port[dpid]），用于后续转发决策。
            2.处理 ARP：直接泛洪。
            3.处理 IPv4：
            4.TCP 且为 SYN：根据已学到的目的端口决定单播或泛洪；若已知端口则下发匹配五元组的流表（优先级 100，idle_timeout=5）并用 PacketOut 发送当前报文。
                    其他 IP（含 ICMP、非 SYN TCP）：若已知目的端口则下发匹配 eth_type/ip_proto/src/dst 的流表（优先级 50，idle_timeout=5）并转发；未知则泛洪。
                    对非 IPv4/ARP 的报文：泛洪。
            整体实现了基于学习的按需（reactive）转发，并对到指定服务器的 TCP SYN 流量进行专门处理，同时通过短期超时让临时流表自动过期"""
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """处理Packet-In消息，实现reactive forwarding和TCP SYN流量处理
        """
        msg = ev.msg# 获取Packet-In消息
        datapath = msg.datapath# 获取数据路径对象
        ofproto = datapath.ofproto  # 获取OpenFlow协议
        parser = datapath.ofproto_parser  # 获取OpenFlow解析器

        dpid = datapath.id# 获取交换机ID
        # 初始化mac_to_port字典
        self.mac_to_port.setdefault(dpid, {})
        # 解析收到的数据包
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)  # 获取以太网协议
        if eth is None:
            return
        src = eth.src
        dst = eth.dst

        in_port = msg.match.get('in_port')# 获取输入端口

        self.logger.info(f'Packet in: dpid={dpid} src={src} dst={dst} in_port={in_port}')

        # 1.学习源MAC地址和端口映射
        self.mac_to_port[dpid][src] = in_port
        self.logger.info(f'Learned MAC to port: dpid={dpid} {src} -> {in_port}')

        # 2.处理ARP包：泛洪 把 IP 地址 → 转换成 MAC 地址
        arp_pkt = pkt.get_protocol(arp.arp)# 获取ARP协议
        if arp_pkt:
            #泛洪ARP包
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]#特殊端口 OFPP_FLOOD
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port,
                                      actions=actions,
                                      data=msg.data)# 发送ARP包
            datapath.send_msg(out)
            return

        ##################################现在 Client 知道 MAC 地址了，它终于可以发送真正的 TCP SYN 握手包了#######################################
        # 3. 处理IPv4包及其他逻辑
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        # --- 第一步：确定转发端口 (查 mac_to_port 表) ---
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # --- 第二步：安装流表 (仅当端口已知且非泛洪时，且为IPv4) ---
        if out_port != ofproto.OFPP_FLOOD and ipv4_pkt:
            ip_proto = ipv4_pkt.proto
            tcp_pkt = pkt.get_protocol(tcp.tcp)

            # === Task 4.1: 通用的 TCP SYN 处理 ===
            # 条件: 协议是TCP + 含有SYN标志
            if (ip_proto == 6 and tcp_pkt and (tcp_pkt.bits & 0x02)):

                # 构造精确匹配 (匹配 IP 和 TCP 端口)
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_dst=dst,
                    eth_type=0x0800,  # IPv4
                    ip_proto=6,  # TCP
                    ipv4_src=ipv4_pkt.src,
                    ipv4_dst=ipv4_pkt.dst,
                    tcp_src=tcp_pkt.src_port,  # 源端口
                    tcp_dst=tcp_pkt.dst_port  # 目的端口
                )
                # 优先级 100 (高优先级处理 TCP 握手流)
                # idle_timeout 5s (Task 2 要求)
                self.add_flow(datapath, 100, match, actions,buffer_id=None, idle_timeout=5)
                self.logger.info("Installed TCP SYN flow: %s -> %s", ipv4_pkt.src, ipv4_pkt.dst)

            # === 普通 IPv4 转发 (ICMP ping 或非首包 TCP) ===
            else:
                # 构造较宽泛的匹配 (匹配到 IP 层即可)
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_dst=dst,
                    eth_type=0x0800,
                    ip_proto=ip_proto,
                    ipv4_src=ipv4_pkt.src,
                    ipv4_dst=ipv4_pkt.dst
                )
                # 优先级 50, idle_timeout 5s
                self.add_flow(datapath, 50, match, actions,buffer_id=None, idle_timeout=5)

        # --- 第三步：发送 Packet-Out ---
        # 无论是泛洪、普通转发还是 TCP 特殊处理，最终都要把包发出去
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath,
                                    buffer_id=msg.buffer_id,
                                    in_port=in_port,
                                    actions=actions,
                                    data=data)
        datapath.send_msg(out)
