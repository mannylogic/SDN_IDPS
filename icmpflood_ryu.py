  1. from ryu.base import app_manager
  2. from ryu.controller import ofp_event
  3. from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, import set_ev_cls
  4. 
  5. from ryu.ofproto import ofproto_v1_3
  6. from ryu.lib.packet import packet
  7. from ryu.lib.packet import ethernet, icmp, ipv4, import ether_types
  8. 
  9. from datetime import datetime
 10. from time import time
 11.  
 12. # Define global variables
 13. threshold = 50  # Attack detection threshold
 14. connections = {}  # Tracked connections
 15. attacker = set()  # Blacklist
 16.  
 17. class SimpleSwitchIDPS(app_manager.RyuApp):
 18.     OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
 19.  
 20.     def __init__(self, *args, **kwargs):
 21.         super(SimpleSwitchIDPS, self).__init__(*args, **kwargs)
 22.         self.mac_to_port = {}
 23.         self.logger.info("ICMP Flood IDPS with Simple Switch functionality started at %s", datetime.now())
 24.  
 25.     @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
 26.     def switch_features_handler(self, ev):
 27.         datapath = ev.msg.datapath
 28.         ofproto = datapath.ofproto
 29.         parser = datapath.ofproto_parser
 30.  
 31.         match = parser.OFPMatch()
 32.         actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
 33.         self.install_flow(datapath, 0, match, actions)
 34.  
 35.     def add_flow(self, datapath, priority, match, actions, buffer_id=None):
 36.         ofproto = datapath.ofproto
 37.         parser = datapath.ofproto_parser
 38.  
 39.         instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
 40.         if buffer_id:
 41.             mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority,
 42.                                     match=match, instructions=inst)
 43.         else:
 44.             mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
 45.                                     match=match, instructions=inst)
 46.         datapath.send_msg(mod)
 47.  
 48.     @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
 49.     def _handle_packet_in(self, ev):
 50.         if ev.msg.msg_len < ev.msg.total_len:
 51.             self.logger.debug("Packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
 52.  
 53.         msg = ev.msg
 54.         datapath = msg.datapath
 55.         ofproto = datapath.ofproto
 56.         parser = datapath.ofproto_parser
 57.         in_port = msg.match['in_port']
 58.  
 59.         pkt = packet.Packet(msg.data)
 60.         eth = pkt.get_protocols(ethernet.ethernet)[0]
 61.  
 62.         dst = eth.dst
 63.         src = eth.src
 64.         dpid = datapath.id
 65.         self.mac_to_port.setdefault(dpid, {})
 66.  
 67.         # Learn a MAC address to avoid FLOOD next time.
 68.         self.mac_to_port[dpid][src] = in_port
 69.  
 70.         # ICMP handling and IDPS
 71.         if eth.ethertype == ether_types.ETH_TYPE_IP:
 72.             ip_pkt = pkt.get_protocol(ipv4.ipv4)
 73.             if ip_pkt.proto == ipv4.inet.IPPROTO_ICMP:
 74.                 self.icmp_func(src, dst, datapath, in_port)
 75.  
 76.         # Simple switch functionality
 77.         if dst in self.mac_to_port[dpid]:
 78.             out_port = self.mac_to_port[dpid][dst]
 79.         else:
 80.             out_port = ofproto.OFPP_FLOOD
 81.  
 82.         actions = [parser.OFPActionOutput(out_port)]
 83.  
 84.         # Install a flow to avoid packet_in next time
 85.         if out_port != ofproto.OFPP_FLOOD:
 86.             match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
 87.             if msg.buffer_id != ofproto.OFP_NO_BUFFER:
 88.                 self.install_flow(datapath, 1, match, actions, msg.buffer_id)
 89.                 return
 90.             else:
 91.                 self.install_flow(datapath, 1, match, actions)
 92.  
 93.         data = None
 94.         if msg.buffer_id == ofproto.OFP_NO_BUFFER:
 95.             data = msg.data
 96.  
 97.         out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
 98.                                   actions=actions, data=data)
 99.         datapath.send_msg(out)
100.  
101.     def mac_blocker(self, src, datapath):
102.         """MAC blocker - kill packets from attackers."""
103.         if src in attacker:
104.             self.logger.info("Blocking traffic from attacker MAC: %s", src)
105.             match = datapath.ofproto_parser.OFPMatch(eth_src=src)
106.             mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, priority=65535,
107.                                                      match=match, instructions=[])
108.             datapath.send_msg(mod)
109.             return True
110.         return False
111.  
112.     def icmp_func(self, src, dst, datapath, in_port):
113.         """Process ICMP packets and detect potential floods."""
114.         global connections, attacker
115.  
116.         if self.mac_blocker(src, datapath):  # Kill blocked packets if necessary
117.             return
118.  
119.         cname = src + ' => ' + dst
120.  
121.         if cname not in connections:
122.             self.new_connection(cname, src, dst)
123.         elif self.check_timeout(cname):
124.             del connections[cname]
125.             return
126.  
127.         self.rl(cname)  # Apply rate limiting for ICMP packets
128.  
129.         if connections[cname]['rl'] > threshold:
130.             self.detect_and_mitigate_attack('rl', cname, datapath)
131.  
132.     def new_connection(self, cname, src, dst):
133.         """Track new ICMP connections."""
134.         global connections
135.         connections[cname] = {
136.             'src': src,
137.             'dst': dst,
138.             'rl': 0,
139.             'time': time(),
140.             'detection_time': None,
141.             'mitigation_time': None
142.         }
143.  
144.     def check_timeout(self, cname):
145.         """Time-out tracked connections after a minute."""
146.         global connections
147.         if time() - connections[cname]['time'] > 60:
148.             return True
149.         return False
150.  
151.     def rl(self, cname):
152.         """Implementation of Rate Limiting algorithm for ICMP."""
153.         global connections
154.         connections[cname]['rl'] += 1
155.  
156.     def detect_and_mitigate_attack(self, algo, cname, datapath):
157.         """Detection and Mitigation Process."""
158.         global connections, attacker
159.  
160.         if not connections[cname]['detection_time']:
161.             connections[cname]['detection_time'] = datetime.now()
162.             self.logger.info('ICMP Flood Attack detected by %s: %s at %s' % (algo, cname, connections[cname]['detection_time']))
163.  
164.         connections[cname]['mitigation_time'] = datetime.now()
165.         self.logger.warning('Mitigation action taken by %s for %s at %s' % (algo, cname, connections[cname]['mitigation_time']))
166.  
167.         attacker.add(connections[cname]['src'])
168.  
169.         match = datapath.ofproto_parser.OFPMatch(eth_src=connections[cname]['src'])
170.         mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, priority=65535,
171.                                                  match=match, instructions=[])
172.         datapath.send_msg(mod)
173.  
174.         detection_to_mitigation_time = (connections[cname]['mitigation_time'] - connections[cname]['detection_time']).total_seconds()
175.         self.logger.info('Speed of mitigation for %s: %s seconds' % (cname, detection_to_mitigation_time))
176.  
177.         del connections[cname]
