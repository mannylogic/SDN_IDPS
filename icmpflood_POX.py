1. from pox.core import core
  2. from pox.lib.revent import EventHalt
  3. import pox.openflow.libopenflow_01 as of
  4. from pox.lib.packet.ethernet import ethernet
  5. from pox.lib.packet.ipv4 import ipv4
  6. from pox.lib.packet.icmp import icmp
  7. from datetime import datetime
  8. from time import time
  9.  
 10. log = core.getLogger()
 11. log.info("ICMP Flood IDPS with MAC blocking going up %s", datetime.now())
 12.  
 13. # Parameters
 14. threshold = 50  # ICMP packet rate threshold
 15. connections = {}  # Tracked connections
 16. attacker = set()  # Blacklist for MAC addresses
 17.  
 18. def icmp_func(event):
 19.     """Receive PacketIn and process ICMP packets."""
 20.     pkt = event.parsed
 21.  
 22.     eth = pkt.find('ethernet')
 23.     icmp_pkt = pkt.find('icmp')
 24.  
 25.     if not eth or not icmp_pkt:
 26.         return
 27.  
 28.     mac_src = eth.src
 29.  
 30.     # Block traffic from known attackers (based on MAC address)
 31.     if mac_src in attacker:
 32.         return EventHalt
 33.  
 34.     cname = f"{mac_src} => {eth.dst}"
 35.  
 36.     if cname not in connections:
 37.         new_connection(cname, pkt)
 38.     elif check_timeout(cname):
 39.         del connections[cname]
 40.         return
 41.  
 42.     rl(cname)  # Apply rate limiting for ICMP packets
 43.  
 44.     if connections[cname]['rl'] > threshold:
 45.         detect_and_mitigate_attack('rl', cname)
 46.  
 47. def new_connection(cname, pkt):
 48.     """Track new ICMP connections based on MAC address."""
 49.     eth = pkt.find('ethernet')
 50.     connections[cname] = {
 51.         'src': eth.src,
 52.         'dst': eth.dst,
 53.         'rl': 0,
 54.         'time': time(),
 55.         'detection_time': None,
 56.         'mitigation_time': None
 57.     }
 58.  
 59. def check_timeout(cname):
 60.     """Timeout tracked connections after a minute."""
 61.     return time() - connections[cname]['time'] > 60
 62.  
 63. def rl(cname):
 64.     """Rate Limiting based on ICMP packet rate."""
 65.     connections[cname]['rl'] += 1
 66.  
 67. def detect_and_mitigate_attack(algo, cname):
 68.     """Detection and Mitigation Process."""
 69.     if not connections[cname]['detection_time']:
 70.         connections[cname]['detection_time'] = datetime.now()
 71.         log.info(f"ICMP Flood attack detected by {algo}: {cname} at {connections[cname]['detection_time']}")
 72.  
 73.     # Mitigation
 74.     connections[cname]['mitigation_time'] = datetime.now()
 75.     log.warning(f"Mitigation action taken by {algo} for {cname} at {connections[cname]['mitigation_time']}")
 76.     mac_src = connections[cname]['src']
 77.     attacker.add(mac_src)
 78.  
 79.     # Send flow mod to block source MAC address
 80.     msg = of.ofp_flow_mod()
 81.     msg.priority = 65535
 82.     msg.match.dl_src = mac_src  # Block based on MAC address
 83.     msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))  # Drop the packet
 84.     for switch in core.openflow.connections:
 85.         switch.send(msg)
 86.  
 87.     detection_to_mitigation_time = (connections[cname]['mitigation_time'] - connections[cname]['detection_time']).total_seconds()
 88.     log.info(f"Speed of mitigation for {cname}: {detection_to_mitigation_time} seconds")
 89.  
 90.     del connections[cname]
 91.  
 92. def clear_flows():
 93.     """Clear flows on all switches."""
 94.     delete_command = of.ofp_flow_mod_command_rev_map['OFPFC_DELETE']
 95.     d = of.ofp_flow_mod(command=delete_command)
 96.     for switch in core.openflow.connections:
 97.         switch.send(d)
 98.  
 99. def launch():
100.     core.openflow.addListenerByName("PacketIn", icmp_func, priority=1)
101.     log.info("ICMP Flood IDPS with MAC blocking launched")
102.  
