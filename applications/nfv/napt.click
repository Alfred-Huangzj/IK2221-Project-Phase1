avg_fd1 :: AverageCounter;
avg_td1 :: AverageCounter;
avg_fd2 :: AverageCounter;
avg_td2 :: AverageCounter;

arpRespondUZ, arpRespondIZ, arpQueryUZ, arpQueryIZ,
icmpIZ, icmpUZ, tcpUZ, dropUZ, dropIZ, icmpEchoDropUZ, icmpEchoDropIZ,
icmpReplyDropUZ, icmpReplyDropIZ :: Counter;

//defination
// napt-eth1: 10.0.0.1
// napt-eth2: 100.0.0.1
fd1 :: FromDevice(napt-eth1, METHOD LINUX, SNIFFER false);
fd2 :: FromDevice(napt-eth2, METHOD LINUX, SNIFFER false);
td1 :: Queue -> avg_td1 -> ToDevice(napt-eth1);
td2 :: Queue -> avg_td2 -> ToDevice(napt-eth2);
// Queue: pull and push commands cannot be connected

// ARP responder for User Zone interface
// Replies to ARP requests for IP 10.0.0.1 with MAC 02:00:00:00:00:01
arpReplyUZ :: ARPResponder(10.0.0.1 02:00:00:00:00:01);


// ARP responder for Inferencing Zone interface
// Replies to ARP requests for IP 100.0.0.1 with MAC 02:00:00:00:00:02
arpReplyIZ :: ARPResponder(100.0.0.1 02:00:00:00:00:02);

arpRequestUZ :: ARPQuerier(10.0.0.1, 02:00:00:00:00:01);
// port0: Used for ARP requests and replies from UZ to IZ
// port1: Used for ARP requests and replies from IZ to UZ

arpRequestIZ :: ARPQuerier(100.0.0.1, 02:00:00:00:00:02);
// port0: Used for ARP requests and replies from UZ to IZ
// port1: Used for ARP requests and replies from IZ to UZ

ipNAT :: IPRewriter(pattern 100.0.0.1 20000-65535 - - 0 1);
// port0: Handles packets going from the user zone to the inference zone 
// port1: Handles packets going from the inference zone back to the user zone

icmpNAT :: ICMPPingRewriter(pattern 100.0.0.1 20000-65535 - - 0 1);
// port0: Handles packets going from the user zone to the inference zone 
// port1: Handles packets going from the inference zone back to the user zone


packetClassifierUZ, packetClassifierIZ :: Classifier(
    12/0806 20/0001, //ARP request
    12/0806 20/0002, //ARP respond
    12/0800, //IP
    - //rest
)

ipClassifierUZ, ipClassifierIZ :: IPClassifier(
    tcp,
    icmp type echo,
    icmp type echo-reply,
    -
)

// input packets from User Zone
fd1 -> avg_fd1 -> packetClassifierUZ;
packetClassifierUZ[0] -> arpQueryUZ -> arpReplyUZ -> td1;
packetClassifierUZ[1] -> arpRespondUZ -> [1]arpRequestUZ;
packetClassifierUZ[2] -> Strip(14) -> CheckIPHeader -> ipClassifierUZ;
// removes the first 14 bytes of a packet (Ethernet header) so that the rest of the pipeline can process the IP header and payload directly
packetClassifierUZ[3] -> dropUZ -> Discard;


ipClassifierUZ[0] -> tcpUZ -> ipNAT[0] -> [0]arpRequestIZ -> td2;
ipClassifierUZ[1] -> icmpUZ -> icmpNAT[0] -> [0]arpRequestIZ -> td2;
ipClassifierUZ[2] -> icmpEchoDropUZ -> Discard;
ipClassifierUZ[3] -> icmpReplyDropUZ -> Discard;

// input packets from Inferencing Zone
fd2 -> avg_fd2 -> packetClassifierIZ;
packetClassifierIZ[0] -> arpQueryIZ -> arpReplyIZ -> td2;
packetClassifierIZ[1] -> arpRespondIZ -> [1]arpRequestIZ;
packetClassifierIZ[2] -> Strip(14) -> CheckIPHeader -> ipClassifierIZ;
packetClassifierIZ[3] -> dropIZ -> Discard;

ipClassifierIZ[0] -> ipNAT[1] -> [0]arpRequestUZ -> td1;
ipClassifierIZ[1] -> icmpEchoDropIZ -> Discard;
ipClassifierIZ[2] -> icmpIZ -> icmpNAT[1] -> [0]arpRequestUZ -> td1;
ipClassifierIZ[3] -> icmpReplyDropIZ -> Discard;




DriverManager(
    pause, 
    print > ./results/napt.report "
    ===================== NAPT Report ====================
    Input Packet Rate (pps): $(add $(avg_fd1.rate) $(avg_fd2.rate))
    Output Packet Rate(pps): $(add $(avg_td1.rate) $(avg_td2.rate))

    Total # of input packets: $(add $(avg_fd1.count) $(avg_fd2.count))
    Total # of output packets: $(add $(avg_td1.count) $(avg_td2.count))

    Total # of ARP request packets: $(add $(arpQueryUZ.count) $(arpQueryIZ.count))
    Total # of ARP reply packets: $(add $(arpRespondUZ.count) $(arpRespondIZ.count))

    Total # of service requests packets: $(add $(tcpUZ.count))
    Total # of ICMP packets: $(add $(icmpUZ.count) $(icmpIZ.count))
    Total # of dropped packets: $(add $(dropUZ.count) $(dropIZ.count) $(icmpEchoDropUZ.count) $(icmpEchoDropIZ.count) $(icmpReplyDropUZ.count) $(icmpReplyDropIZ.count))
    ======================================================",
    stop
    );