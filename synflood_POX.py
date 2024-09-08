1. from pox.core import core
  2. from pox.lib.revent import EventHalt
  3. import pox.openflow.libopenflow_01 as of
  4. from pox.lib.packet.ethernet import ethernet
  5. from pox.lib.packet.ipv4 import ipv4
  6. from pox.lib.packet.tcp import tcp
  7. from datetime import datetime
  8. from time import time
  9.  
 10. log = core.getLogger()
 11. log.info("TCP SYN Flood IDPS with MAC blocking going up %s", datetime.now())
 12.  
 13. # Parameters
 14. threshold = 50  # SYN packet rate threshold
 15. connections = {}  # Tracked connections
 16. attacker = set()  # Blacklist for MAC addresses
 17.  
 18. def tcp_func(event):
 19.     """Receive PacketIn and process TCP packets."""
 20.     pkt = event.parsed
 21.  
 22.     eth = pkt.find('ethernet')
 23.     ipv4_pkt = pkt.find('ipv4')
 24.     tcp_pkt = pkt.find('tcp')
 25.  
 26.     if not eth or not ipv4_pkt or not tcp_pkt:
 27.         return
 28.  
 29.     mac_src = eth.src
 30.  
 31.     # Block traffic from known attackers (based on MAC address)
 32.     if mac_src in attacker:
 33.         return EventHalt
 34.  
 35.     if tcp_pkt.SYN and not tcp_pkt.ACK:  # SYN packet
 36.         cname = f"{mac_src} => {eth.dst}"
 37.  
 38.         if cname not in connections:
 39.             new_connection(cname, pkt)
 40.         elif check_timeout(cname):
 41.             del connections[cname]
 42.             return
 43.  
 44.         rl(cname)  # Apply rate limiting for SYN packets
 45.  
 46.         if connections[cname]['rl'] > threshold:
 47.             detect_and_mitigate_attack('rl', cname)
 48.  
 49. def new_connection(cname, pkt):
 50.     """Track new TCP connections based on MAC address."""
 51.     eth = pkt.find('ethernet')
 52.     connections[cname] = {
 53.         'src': eth.src,
 54.         'dst': eth.dst,
 55.         'rl': 0,
 56.         'time': time(),
 57.         'detection_time': None,
 58.         'mitigation_time': None
 59.     }
 60.  
 61. def check_timeout(cname):
 62.     """Timeout tracked connections after a minute."""
 63.     return time() - connections[cname]['time'] > 60
 64.  
 65. def rl(cname):
 66.     """Rate Limiting based on SYN packet rate."""
 67.     connections[cname]['rl'] += 1
 68.  
 69. def detect_and_mitigate_attack(algo, cname):
 70.     """Detection and Mitigation Process."""
 71.     if not connections[cname]['detection_time']:
 72.         connections[cname]['detection_time'] = datetime.now()
 73.         log.info(f"Attack detected by {algo}: {cname} at {connections[cname]['detection_time']}")
 74.  
 75.     # Mitigation
 76.     connections[cname]['mitigation_time'] = datetime.now()
 77.     log.warning(f"Mitigation action taken by {algo} for {cname} at {connections[cname]['mitigation_time']}")
 78.     mac_src = connections[cname]['src']
 79.     attacker.add(mac_src)
 80.  
 81.     # Send flow mod to block source MAC address
 82.     msg = of.ofp_flow_mod()
 83.     msg.priority = 65535
 84.     msg.match.dl_src = mac_src  # Block based on MAC address
 85.     msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))  # Drop the packet
 86.     for switch in core.openflow.connections:
 87.         switch.send(msg)
 88.  
 89.     detection_to_mitigation_time = (connections[cname]['mitigation_time'] - connections[cname]['detection_time']).total_seconds()
 90.     log.info(f"Speed of mitigation for {cname}: {detection_to_mitigation_time} seconds")
 91.  
 92.     del connections[cname]
 93.  
 94. def clear_flows():
 95.     """Clear flows on all switches."""
 96.     delete_command = of.ofp_flow_mod_command_rev_map['OFPFC_DELETE']
 97.     d = of.ofp_flow_mod(command=delete_command)
 98.     for switch in core.openflow.connections:
 99.         switch.send(d)
100.  
101. def launch():
102.     core.openflow.addListenerByName("PacketIn", tcp_func, priority=1)
    	log.info("TCP SYN Flood IDPS with MAC blocking launched") 
