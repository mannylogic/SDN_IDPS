1. from ryu.base import app_manager
  2. from datetime import datetime
  3. import time
  4. from ryu.controller.handler import set_ev_cls, CONFIG_DISPATCHER, MAIN_DISPATCHER 
  5. from ryu.controller import ofp_event 
  6. 
  7. from ryu.lib.packet import ethernet, ipv4, tcp, packet
  8. 

  9. 
 10.  
 11. class EnhancedIDPS(app_manager.RyuApp):
 12.     OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
 13.  
 14.     def __init__(self, *args, **kwargs):
 15.         super(EnhancedIDPS, self).__init__(*args, **kwargs)
 16.         self.connections = {}
 17.         self.attacker = set()
 18.         self.threshold = 100  # Attack detection threshold
 19.         self.logger.info("Ryu IDPS starting up at %s", datetime.now())  
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
 58.         # Handle ARP packets
 59.         if eth.ethertype == 0x0806:
 60.             self.handle_arp(datapath, in_port, pkt)
 61.             return
 62.  
 63.         ip_pkt = pkt.get_protocol(ipv4.ipv4)
 64.         tcp_pkt = pkt.get_protocol(tcp.tcp)
 65.  
 66.         if not tcp_pkt or tcp_pkt.bits & (tcp.TCP_SYN | tcp.TCP_ACK) != tcp.TCP_SYN:
 67.             # Forward other packets normally
 68.             self.forward_packet(datapath, in_port, msg.data)
 69.             return
 70.  
 71.         cname = str(ip_pkt.src) + ' => ' + str(ip_pkt.dst)
 72.  
 73.         if cname not in self.connections:
 74.             self.new_connection(cname, ip_pkt.src, ip_pkt.dst)
 75.         elif self.check_timeout(cname):
 76.             del self.connections[cname]
 77.             return
 78.  
 79.         if cname in self.connections:
 80.             self.trw(cname, tcp_pkt)
 81.             self.rl(cname)
 82.  
 83.             if self.connections[cname]['trw'] > self.threshold:
 84.                 self.mitigate_attack(datapath, ip_pkt.src, 'trw', cname)
 85.             elif self.connections[cname]['rl'] > self.threshold:
 86.                 self.mitigate_attack(datapath, ip_pkt.src, 'rl', cname)
 87.             else:
 88.                 # Forward packets of non-attack connections
 89.                 self.forward_packet(datapath, in_port, msg.data)
 90.  
 91.     def forward_packet(self, datapath, in_port, data):
 92.         """Forward packets to the appropriate port."""
 93.         ofproto = datapath.ofproto
 94.         parser = datapath.ofproto_parser
 95.         actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
 96.         out = parser.OFPPacketOut(
 97.             datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
 98.             in_port=in_port, actions=actions, data=data)
 99.         datapath.send_msg(out)
100.  
101.     def handle_arp(self, datapath, in_port, pkt):
102.         """Handle ARP requests and replies."""
103.         ofproto = datapath.ofproto
104.         parser = datapath.ofproto_parser
105.  
106.         eth_pkt = pkt.get_protocol(ethernet.ethernet)
107.         arp_pkt = pkt.get_protocol(arp.arp)
108.  
109.         # Create ARP reply or forward ARP request
110.         if arp_pkt.opcode == arp.ARP_REQUEST:
111.             self.forward_packet(datapath, in_port, pkt.data)
112.         elif arp_pkt.opcode == arp.ARP_REPLY:
113.             self.forward_packet(datapath, in_port, pkt.data)
114.  
115.     def new_connection(self, cname, src_ip, dst_ip):
116.         self.connections[cname] = {
117.             'src': src_ip,
118.             'dst': dst_ip,
119.             'trw': 0,
120.             'rl': 0,
121.             'start_time': time.time()
122.         }
123.  
124.     def check_timeout(self, cname):
125.         return time.time() - self.connections[cname]['start_time'] > 60
126.  
127.     def trw(self, cname, tcp_pkt):
128.         if tcp_pkt.bits == tcp.TCP_SYN:
129.             self.connections[cname]['trw'] += 1
130.         elif tcp_pkt.bits == (tcp.TCP_SYN | tcp.TCP_ACK):
131.             self.connections[cname]['trw'] -= 1
132.  
133.     def rl(self, cname):
134.         self.connections[cname]['rl'] += 1
135.  
136.     def mitigate_attack(self, datapath, src_ip, algo, cname):
137.         if src_ip in self.attacker:
138.             return
139.  
140.         detection_time = time.time()
141.         self.logger.info('Attack detected: %s at %s', cname, datetime.now().time())
142.         self.attacker.add(src_ip)
143.  
144.         # Use ipv4_src instead of eth_src for IP addresses
145.         match = datapath.ofproto_parser.OFPMatch(ipv4_src=src_ip)
146.         actions = []
147.         self.add_flow(datapath, 65535, match, actions)
148.  
149.         mitigation_time = time.time()
150.         self.logger.warning('Mitigation action taken for %s at %s', cname, datetime.now().time())  
151.  
152.         speed_of_mitigation = mitigation_time - self.connections[cname]['start_time']
153.         self.logger.info('Speed of mitigation: %.6f seconds', speed_of_mitigation) 
154.  
155.         del self.connections[cname]
156.  
