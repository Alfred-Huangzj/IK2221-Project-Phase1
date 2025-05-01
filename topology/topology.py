
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Switch
from mininet.cli import CLI
from mininet.node import RemoteController, OVSController, Controller
from mininet.node import OVSSwitch
import subprocess
import signal
import os
import time

class MyTopo(Topo):
    def __init__(self):

        # Initialize topology
        Topo.__init__(self)

        # This is the implementation of the topology for the project
        # Please update the IP addresses to the correct ones
        # You can update the topology as you see fit

        # Initialize hosts for user zone
        h1 = self.addHost('h1', ip='10.0.0.50/24')
        h2 = self.addHost('h2', ip='10.0.0.51/24')
        # Initialize switch for user zone
        s1 = self.addSwitch('s1', dpid="1")
        # Connect hosts to switch
        self.addLink(h1, s1)
        self.addLink(h2, s1)

        # Initialize napt between user zone and inferencing zone
        napt = self.addSwitch('napt', dpid="4") # dpid is 4 because we have 3 normal switches in the topology
        # Connect user zone switch to napt
        self.addLink(s1, napt)
        # self.addLink(s1, napt, intfName2='napt-eth1', params2={'mac': '02:00:00:00:00:01'})

        # Initalize access switch for inferencing zone
        s2 = self.addSwitch('s2', dpid="2")
        # Connect napt to access switch
        self.addLink(napt, s2)
        # self.addLink(napt, s2, intfName1='napt-eth2', params1={'mac': '02:00:00:00:00:02'})

        # Initialize ids switch for inferencing zone
        ids = self.addSwitch('ids', dpid="5") # dpid is 5 because we have 3 normal switches and 1 napt switch in the topology
        # Connect access switch to ids switch
        self.addLink(s2, ids)

        # Create inspection server for inferencing zone
        insp = self.addHost('insp', ip='100.0.0.30/24')
        
        # Connect inspection server to ids switch
        self.addLink(insp, ids)

        # Create load balancer for inferencing zone
        lb1 = self.addSwitch('lb1', dpid="6")
        # Connect ids switch to load balancer
        self.addLink(ids, lb1)

        # Create switch to connect load balancer to inferencing servers
        s3 = self.addSwitch('s3', dpid="3")
        # Connect load balancer to switch
        self.addLink(lb1, s3)

        # Create inferencing servers 
        llm1 = self.addHost('llm1', ip='100.0.0.40/24')
        llm2 = self.addHost('llm2', ip='100.0.0.41/24')
        llm3 = self.addHost('llm3', ip='100.0.0.42/24')

        # Connect inferencing servers to switch
        self.addLink(llm1, s3)
        self.addLink(llm2, s3)
        self.addLink(llm3, s3)

def startup_services(net):
    # Start http services and executing commands you require on each host...
    
    # Default route for hosts
    net.get('h1').cmd('ip route add default via 10.0.0.1')
    net.get('h1').cmd('arp -s 10.0.0.1 02:00:00:00:00:01')
    net.get('h1').cmd('arp -s 100.0.0.45 00:00:00:00:00:45')

    net.get('h2').cmd('ip route add default via 10.0.0.1')
    net.get('h2').cmd('arp -s 10.0.0.1 02:00:00:00:00:01')
    net.get('h2').cmd('arp -s 100.0.0.45 00:00:00:00:00:45')

    # Default route for llm servers
    net.get('llm1').cmd('ip route add default via 100.0.0.1')
    net.get('llm2').cmd('ip route add default via 100.0.0.1')
    net.get('llm3').cmd('ip route add default via 100.0.0.1')
    net.get('insp').cmd('ip route add default via 100.0.0.1')
    
    # 配置NAPT接口的IP地址
    net.get('napt').cmd('ifconfig napt-eth1 10.0.0.1 netmask 255.255.255.0')
    net.get('napt').cmd('ifconfig napt-eth2 100.0.0.1 netmask 255.255.255.0')
    net.get('napt').cmd('ifconfig napt-eth1 hw ether 02:00:00:00:00:01')
    net.get('napt').cmd('ifconfig napt-eth2 hw ether 02:00:00:00:00:02')
    net.get('napt').cmd('ifconfig napt-eth1 10.0.0.1/24 up')
    net.get('napt').cmd('ifconfig napt-eth2 100.0.0.1/24 up')
    # net.get('napt').cmd('arp -s 10.0.0.1 02:00:00:00:00:01')
    # net.get('napt').cmd('arp -s 100.0.0.1 02:00:00:00:00:02')
    
    # 开启IP转发
    net.get('napt').cmd('sysctl -w net.ipv4.ip_forward=1')

    # Setup static ARP only for lb1
    # net.get('lb1').cmd('arp -s 100.0.0.45 00:00:00:00:00:45')
    print("Static ARP entry configured for lb1.")
    
    
    print("Starting services...")

    # Start HTTP servers on llm1-3
    # For each LLM server, create a directory and start a simple HTTP server
    for i in range(1, 4):
        server = net.get(f'llm{i}')
        server.cmd('mkdir -p /home/mininet/web')

        # Creat 5 HTML pages for each server
        for j in range(1, 6):
            server.cmd(f'echo "<html><body><h1>Test Page {j} from LLM Server {i}</h1></body></html>" > /home/mininet/web/page{j}.html')
        server.cmd(f'cd /home/mininet/web && python3 -m http.server 80 &')

    print("HTTP services started")
    
    return





# topos = {'mytopo': (lambda: MyTopo())}

if __name__ == "__main__":

    # Create topology
    topo = MyTopo()

    ctrl = RemoteController("c0", ip="127.0.0.1", port=6633)

    # Create the network
    net = Mininet(topo=topo,
                  switch=OVSSwitch,
                  controller=ctrl,
                  autoSetMacs=True,
                  autoStaticArp=True,
                  build=True,
                  cleanup=True)

    startup_services(net)
    # Start the  network
    net.start()

    # Start the CLI
    CLI(net)

    # You may need some commands before stopping the network! If you don't, leave it empty
    ### COMPLETE THIS PART ###
    net.stop()
