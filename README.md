##
This research work explores the implementation of an Intrusion Detection and
Prevention System (IDPS) using Software-Defined Networking (SDN)
to defend against common Denial-of-Service (DoS) attacks,
specifically SYN Flood, Port Scanning, and ICMP Flood attacks. The
study focuses on evaluating three widely-used SDN controllers—POX,
Ryu, and Faucet and comparing their performance in mitigating these
threats.

I created a network testbed using Ubuntu Virtual
Machines (VM) and enlisting an hypervisor (Virtual Box), Open
vSwitch (OvS) acting as the virtual switch, a VM that served as the
SDN controller. Three IDPS scripts were used to detect and mitigate
the attacks (one for each attack), two of which are bespoke scripts,
whilst one was sourced from a top paper with slight changes made to
it. The IDPS employed Credit- Based Threshold Random Walk and
Rate limiting algorithms. Key performance metrics, including detection
time, mitigation time, and the impact on legitimate traffic by measuring
RTT, were recorded and analyzed.

I have uploaded the full paper as well as Code used
