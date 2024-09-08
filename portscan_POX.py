  1. from pox.core import core
  2. from pox.lib.revent import EventHalt
  3. import pox.openflow.libopenflow_01 as of
  4. from datetime import datetime
  5. from time import time
  6.  
  7. # Create a logger for this component
  8. log = core.getLogger()
  9. log.info("IDPS going up %s", datetime.now())
 10.  
 11. threshold = 100  # Attack detection threshold
 12. connections = {}  # Tracked connections
 13. attacker = set()  # Blacklist
 14.  
 15. def tcp_func(event, c=None, t=threshold):
 16.     """Receive PacketIn and process TCP packets."""
 17.     if c is None:
 18.         c = connections
 19.     pkt = event.parsed
 20.  
 21.     mac_blocker(str(pkt.src))  # Kill blocked packets
 22.  
 23.     cname = str(pkt.src) + ' => ' + str(pkt.dst)
 24.     p = event.parsed.find('tcp')  # TCP packet attributes
 25.  
 26.     if not p:
 27.         return
 28.  
 29.     if True in [p.FIN, p.RST, p.PSH, p.URG, p.ECN, p.CWR]:
 30.         return
 31.  
 32.     if p.SYN and not p.ACK:
 33.         if cname not in c:
 34.             new_connection(cname, pkt)
 35.         elif check_timeout(cname):
 36.             del c[cname]
 37.             return
 38.  
 39.         trw(cname, syn=True, ack=False)
 40.         rl(cname)
 41.  
 42.         if c[cname]['trw'] > t:
 43.             detect_and_mitigate_attack('trw', cname)
 44.         elif c[cname]['rl'] > t:
 45.             detect_and_mitigate_attack('rl', cname)
 46.  
 47.     elif p.SYN and p.ACK:
 48.         rev_cname = str(pkt.dst) + ' => ' + str(pkt.src)
 49.         if rev_cname in c:
 50.             trw(rev_cname, syn=True, ack=True)
 51.  
 52. def mac_blocker(ethernet_src):
 53.     """MAC blocker - kill packets from attackers."""
 54.     global attacker
 55.     if ethernet_src in attacker:
 56.         return EventHalt
 57.  
 58. def new_connection(cname, pkt, c=None):
 59.     """Track new connections."""
 60.     if c is None:
 61.         c = connections
 62.     c[cname] = {
 63.         'src': pkt.src,
 64.         'dst': pkt.dst,
 65.         'trw': 0,
 66.         'rl': 0,
 67.         'time': time(),
 68.         'detection_time': None,
 69.         'mitigation_time': None
 70.     }
 71.  
 72. def check_timeout(cname, c=None):
 73.     """Time-out tracked connections after a minute."""
 74.     if c is None:
 75.         c = connections
 76.     if time() - c[cname]['time'] > 60:
 77.         return True
 78.     else:
 79.         return False
 80.  
 81. def trw(cname, syn, ack, c=None, t=threshold):
 82.     """Implementation of CB-TRW algorithm."""
 83.     if c is None:
 84.         c = connections
 85.     log.debug('trw %s' % str(c[cname]['trw']), syn, ack)
 86.     if syn and not ack:
 87.         c[cname]['trw'] += 1
 88.     elif syn and ack:
 89.         c[cname]['trw'] -= 1
 90.  
 91. def rl(cname, c=None, t=threshold):
 92.     """Implementation of Rate Limiting algorithm."""
 93.     if c is None:
 94.         c = connections
 95.     log.debug('rl %s' % str(c[cname]['rl']))
 96.     c[cname]['rl'] += 1
 97.  
 98. def detect_and_mitigate_attack(algo, cname, c=None):
 99.     """Detection and Mitigation Process."""
100.     if c is None:
101.         c = connections
102.     # Record the detection time
103.     if not c[cname]['detection_time']:
104.         c[cname]['detection_time'] = datetime.now()
105.         log.info('Attack detected by %s: %s at %s' % (algo, cname, c[cname]['detection_time']))
106.  
107.     # Perform mitigation
108.     c[cname]['mitigation_time'] = datetime.now()
109.     log.warning('Mitigation action taken by %s for %s at %s' % (algo, cname, c[cname]['mitigation_time']))
110.  
111.     # Add to attacker blacklist and send flow mod to block
112.     attacker.add(str(c[cname]['src']))
113.     msg = of.ofp_flow_mod()
114.     msg.priority = 65535
115.     msg.match.dl_src = c[cname]['src']
116.     for switch in core.openflow.connections:
117.         switch.send(msg)
118.     
119.     # Calculate and log the time difference between detection and mitigation
120.     detection_to_mitigation_time = (c[cname]['mitigation_time'] - c[cname]['detection_time']).total_seconds()
121.     log.info('Speed of mitigation for %s: %s seconds' % (cname, detection_to_mitigation_time))
122.  
123.     # Remove the connection record
124.     del c[cname]
125.  
126. def clear_flows():
127.     """Clear flows on all switches."""
128.     delete_command = of.ofp_flow_mod_command_rev_map['OFPFC_DELETE']
129.     d = of.ofp_flow_mod(command=delete_command)
130.     for switch in core.openflow.connections:
131.         switch.send(d)
132.  
133. def launch():
134.     core.openflow.addListenerByName("PacketIn", tcp_func, priority=1)
135.  
