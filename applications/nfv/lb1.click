avg_clientInputCount:: AverageCounter;
avg_serverInputCount:: AverageCounter;
avg_clientOutputCount:: AverageCounter;
avg_serverOutputCount :: AverageCounter;


arpReqCount, arpReqCount1, arpQueCount, arpQueCount1, ipCount, ipCount1, icmpCount,
icmpCount1, dropCount, dropCount1, dropCount2, dropCount3 :: Counter;

// eth1: between ids and lb1
// eth2: between lb1 and sw3


// Input channels from devices
// "SNIFFER false" allows click steals the packet from the kernel
fd1 :: FromDevice(lb1-eth1, METHOD LINUX, SNIFFER false);
fd2 :: FromDevice(lb1-eth2, METHOD LINUX, SNIFFER false);


// Output channels to devices
td1 :: ToDevice(lb1-eth1, METHOD LINUX);
td2 :: ToDevice(lb1-eth2, METHOD LINUX);


// lb1-eth1 MAC: e2:2b:0a:2c:17:4f
// lb1-eth2 MAC: 46:30:ac:19:88:09


// numbers are packer header match patterns
// "12/0806": 12 means offset 12 bytes from the start of the packet (Ethernet header's EtherType field), 0806 is the EtherType for ARP
// "20/0001": means offset 32 bytes from the start, 0001 is the ARP opcode for "request"
clientClassifier, serverClassifier :: Classifier(
    12/0806 20/0001, //ARP requrest
    12/0806 20/0002, //ARP respond
    12/0800, //IP
    - ); //others


ipPacketClassifierClient :: IPClassifier(
    dst 100.0.0.45 and icmp, //ICMP (ping)
    dst 100.0.0.45 port 80 and tcp, //tcp
    -); //others


ipPacketClassifierServer :: IPClassifier(
    dst 100.0.0.45 and icmp type echo, //ICMP to lb
    src port 80 and tcp, //tcp
    -); //others


arpQuerierClient :: ARPQuerier(100.0.0.45/24, e2:2b:0a:2c:17:4f);
arpQuerierServer :: ARPQuerier(100.0.0.45/24, 46:30:ac:19:88:09);
// arpq has two input ports：
// input 0: For IP packets that need ARP resolution
// input 1: For ARP replies (so the ARPQuerier can update its ARP cache/table with new information)


arpRespondClient :: ARPResponder(100.0.0.45/24 e2:2b:0a:2c:17:4f);
arpRespondServer :: ARPResponder(100.0.0.45/24 46:30:ac:19:88:09);

// Queue: pull and push commands cannot be connected
toClient :: Queue(1024) -> avg_clientOutputCount -> td1;
toServer :: Queue(1024) -> avg_serverOutputCount -> td2;

ipPacketClient :: GetIPAddress(16) -> CheckIPHeader -> [0]arpQuerierClient -> toClient;
ipPacketServer :: GetIPAddress(16) -> CheckIPHeader -> [0]arpQuerierServer -> toServer;

ipRewrite :: IPRewriter (roundRobin);
// input 0: handles the packets from clients to the virtual IP
// input 1: handles the packets from servers back to the clients

roundRobin :: RoundRobinIPMapper(
    100.0.0.45 - 100.0.0.40 - 0 1,
    100.0.0.45 - 100.0.0.41 - 0 1,
    100.0.0.45 - 100.0.0.42 - 0 1);

ipRewrite[0] -> ipPacketServer;
ipRewrite[1] -> ipPacketClient;

//from client
fd1 -> avg_clientInputCount -> clientClassifier;

clientClassifier[0] -> arpReqCount -> arpRespondClient -> toClient;
// ARP request
clientClassifier[1] -> arpQueCount -> [1]arpQuerierClient;
// ARP respond
clientClassifier[2] -> ipCount -> Strip(14) -> CheckIPHeader -> ipPacketClassifierClient;
// IP
clientClassifier[3] -> dropCount1 -> Discard;
// others

ipPacketClassifierClient[0] -> icmpCount -> ICMPPingResponder -> ipPacketClient;
// ICMP
ipPacketClassifierClient[1] -> [0]ipRewrite;
//TCP
ipPacketClassifierClient[2] -> dropCount -> Discard;
// others



//from server
fd2 -> avg_serverInputCount -> serverClassifier;

serverClassifier[0] -> arpReqCount1 -> arpRespondServer -> toServer;
// ARP request
serverClassifier[1] -> arpQueCount1 -> [1]arpQuerierServer;
// ARP respond
serverClassifier[2] -> ipCount1 -> Strip(14) -> CheckIPHeader -> ipPacketClassifierServer;
// IP
serverClassifier[3] -> dropCount2 -> Discard;
// others

ipPacketClassifierServer[0] -> icmpCount1 -> ICMPPingResponder -> ipPacketServer;
// ICMP to lb
ipPacketClassifierServer[1] -> [0]ipRewrite;
// TCP
ipPacketClassifierServer[2] -> dropCount3 -> Discard;
// others


DriverManager(
    pause, 
    print > ./results/lb1.report "
    ==============lb1.report===============
    Input Packet Rate (pps):  $(add $(avg_clientInputCount.rate) $(avg_serverInputCount.rate))
    Output Packet Rate (pps):  $(add $(avg_clientOutputCount.rate) $(avg_serverOutputCount.rate))

    Total # of input packet:  $(add $(avg_clientInputCount.count) $(avg_serverInputCount.count))
    Total # of output packet:  $(add $(avg_clientOutputCount.count) $(avg_serverOutputCount.count))

    Total # of ARP requests:  $(add $(arpReqCount.count) $(arpReqCount1.count))
    Total # of ARP responses:  $(add $(arpQueCount.count) $(arpQueCount1.count))

    Total # of service packets:  $(add $(ipCount.count) $(ipCount1.count))
    Total # of ICMP packets:  $(add $(icmpCount.count) $(icmpCount1.count))
    Total # of dropped packets:  $(add $(dropCount.count) $(dropCount1.count) $(dropCount2.count) $(dropCount3.count))
    ======================================",
    stop
    );