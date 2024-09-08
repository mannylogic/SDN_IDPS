1. ryu.controller import ofp_event
  2. from ryu.base import app_manager
  3. from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, import set_ev_cls
  4. from ryu.ofproto import ofproto_v1_3
  5. 
  6. 
  7. from ryu.lib.packet import ethernet, ipv4, tcp, packet
  8. from datetime import datetime
  9. import time
 10.  
 11. class SynFloodMitigation(app_manager.RyuApp):
 12.     OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
 13.  
 14.     def __init__(self, *args, **kwargs):
 15.         super(SynFloodMitigation, self).__init__(*args, **kwargs)
 16.         self.connections = {}
 17.         self.attacker = set()
 18.         self.threshold = 50  # Attack detection threshold
 19.         self.logger.info("SYN Flood IDPS starting up at %s", datetime.now())
 20.  
 21.     @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
 22.     def switch_features_handler(self, ev):
 23.         datapath = ev.msg.datapath
 24.         ofproto = datapath.ofproto
 25.         parser = datapath.ofproto_parser
 26.  
 27.         # Install the table-miss flow entry to send unknown packets to the controller
 28.         match = parser.OFPMatch()
 29.         actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
 30.         self.add_flow(datapath, 0, match, actions)
 31.  
 32.     def add_flow(self, datapath, priority, match, actions):
 33.         ofproto = datapath.ofproto
 34.         parser = datapath.ofproto_parser
 35.  
 36.         inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
 37.  
 38.         mod = parser.OFPFlowMod(
 39.             datapath=datapath, priority=priority, match=match,
 40.             instructions=inst)
 41.         datapath.send_msg(mod)
 42.  
 43.     @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
 44.     def _packet_in_handler(self, ev):
 45.         msg = ev.msg
 46.         datapath = msg.datapath
 47.         ofproto = datapath.ofproto
 48.         parser = datapath.ofproto_parser
 49.         in_port = msg.match['in_port']
 50.  
 51.         pkt = packet.Packet(msg.data)
 52.         eth = pkt.get_protocol(ethernet.ethernet)
 53.  
 54.         # Ignore packets from attackers
 55.         if eth.src in self.attacker:
 56.             return
 57.  
 58.         ip_pkt = pkt.get_protocol(ipv4.ipv4)
 59.         tcp_pkt = pkt.get_protocol(tcp.tcp)
 60.  
 61.         if not tcp_pkt or tcp_pkt.bits & (tcp.TCP_SYN | tcp.TCP_ACK) != tcp.TCP_SYN:
 62.             # Forward other packets normally
 63.             self.forward_packet(datapath, in_port, msg.data)
 64.             return
 65.  
 66.         cname = f"{ip_pkt.src} => {ip_pkt.dst}"
 67.  
 68.         if cname not in self.connections:
 69.             self.new_connection(cname, eth.src, eth.dst)
 70.         elif self.check_timeout(cname):
 71.             del self.connections[cname]
 72.             return
 73.  
 74.         if cname in self.connections:
 75.             self.trw(cname, tcp_pkt)
 76.             self.rl(cname)
 77.  
 78.             if self.connections[cname]['trw'] > self.threshold:
 79.                 self.mitigate_attack(datapath, eth.src, 'trw', cname)
 80.             elif self.connections[cname]['rl'] > self.threshold:
 81.                 self.mitigate_attack(datapath, eth.src, 'rl', cname)
 82.             else:
 83.                 # Forward packets of non-attack connections
 84.                 self.forward_packet(datapath, in_port, msg.data)
 85.  
 86.     def forward_packet(self, datapath, in_port, data):
 87.         """Forward packets to the appropriate port."""
 88.         ofproto = datapath.ofproto
 89.         parser = datapath.ofproto_parser
 90.         actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
 91.         out = parser.OFPPacketOut(
 92.             datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
 93.             in_port=in_port, actions=actions, data=data)
 94.         datapath.send_msg(out)
 95.  
 96.     def new_connection(self, cname, src_mac, dst_mac):
 97.         self.connections[cname] = {
 98.             'src_mac': src_mac,
 99.             'dst_mac': dst_mac,
100.             'trw': 0,
101.             'rl': 0,
102.             'start_time': time.time()
103.         }
104.  
105.     def check_timeout(self, cname):
106.         return time.time() - self.connections[cname]['start_time'] > 60
107.  
108.     def trw(self, cname, tcp_pkt):
109.         if tcp_pkt.bits == tcp.TCP_SYN:
110.             self.connections[cname]['trw'] += 1
111.         elif tcp_pkt.bits == (tcp.TCP_SYN | tcp.TCP_ACK):
112.             self.connections[cname]['trw'] -= 1
113.  
114.     def rl(self, cname):
115.         self.connections[cname]['rl'] += 1
116.  
117.     def mitigate_attack(self, datapath, src_mac, algo, cname):
118.         if src_mac in self.attacker:
119.             return
120.  
121.         detection_time = time.time()
122.         self.logger.info('Attack detected by %s: %s at %s', algo, cname, datetime.now().time())
123.         self.attacker.add(src_mac)
124.  
125.         match = datapath.ofproto_parser.OFPMatch(eth_src=src_mac)
126.         actions = []
127.         self.add_flow(datapath, 65535, match, actions)
128.  
129.         mitigation_time = time.time()
130.         self.logger.warning('Mitigation action taken by %s for %s at %s', algo, cname, datetime.now().time())
131.  
132.         # Calculate the speed of mitigation correctly
133.         speed_of_mitigation = mitigation_time - detection_time
134.         self.logger.info('Speed of mitigation: %.6f seconds', speed_of_mitigation)
135.  
136.         del self.connections[cname]
137.  
