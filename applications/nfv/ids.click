// Define the port names
// * eth0: Default port of Mininet host
// * eth1: Port connected to the sw2
// * eth2: Port connected to the Insp device
// * eth3: Port connected to the lb1
define($IN ids-eth1, $INSP ids-eth2, $OUT ids-eth3);

// Define the report path
define($REPORT_PATH results/ids.report);

// Script will run as soon as the router starts
Script(print "IDS forwarder on ids-eth1 & ids-eth3, IDS connect Insp via ids-eth2");

// Related Counters

// Packet rate counter
rate_fr_s1 :: AverageCounter;
rate_fr_lb1 :: AverageCounter;
rate_to_s1 :: AverageCounter;
rate_to_lb1 :: AverageCounter;
rate_to_insp :: AverageCounter;



// === Edge Data flow ===
// Incoming traffic flow & counter

// fr_s1: Data from the sw2 to the IDS
// fr_lb1: Data from the lb1 to the IDS
fr_s1 :: FromDevice($IN, SNIFFER false, METHOD LINUX, SNIFFER false);
fr_lb1 :: FromDevice($OUT, SNIFFER false, METHOD LINUX, SNIFFER false);

// to_s1: Data from the IDS to the sw2
to_s1 :: Queue -> rate_to_s1 -> ToDevice($IN, METHOD LINUX);
to_lb1 :: Queue  -> rate_to_lb1 -> ToDevice($OUT, METHOD LINUX);
to_insp :: Queue -> rate_to_insp -> ToDevice($INSP, METHOD LINUX);

// Packet Classifier

// ===== Level 1: Ethernet header =====

// ==================
// element: s1_ethernet_classifier
// Description: Data fr_s1, Classify the packet with Ethernet header
//
// 1. ARP transparently transmitted to the output port
// 2. IPv4 for further classification
// 3. Others dropped
// =================

s1_ethernet_classifier :: Classifier(
	12/0806,    // ARP (offset 12, ARP 0x0806)
	12/0800,    // IPv4 (offset 12, IPv4 0x0800)
	-           // Others
);

// ==================
// element: lb1_ethernet_classifier
// Description: Data fr_lb1, Classify the packet with Ethernet header
//
// 1. ARP transparently transmitted to the output port
// 2. IPv4 for further classification
// 3. Others dropped
// =================

lb1_ethernet_classifier :: Classifier(
    12/0806,    // ARP (offset 12, ARP 0x0806)
    12/0800,    // IPv4 (offset 12, IPv4 0x0800)
    -           // Others
);

// ==================
// Counter of ethernet classifier
// 1. ctr_arp: ARP packets
// 2. ctr_ip: IPv4 packets (e.g., ICMP, TCP, UDP etc.)
// 3. ctr_ethernet_drop: Others
// =================
ctr_s1_arp :: Counter;
ctr_s1_ip :: Counter;
ctr_s1_ethernet_drop :: Counter;

ctr_lb1_arp :: Counter;
ctr_lb1_ip :: Counter;
ctr_lb1_ethernet_drop :: Counter;


// ===== Level 2: IP + TCP header =====

// ==================
// element: s1_ip_classifier
// Description: Data fr_s1, Classify the ICMP and TCP signaling packets
// 
// 1. Offset 23 (Protoco): ICMP (0x01)
// 2. Offset 47 (TCP Flag): TCP type packets
// 3. Others for further classification (HTTP port 80)
// ==================

s1_ip_classifier :: Classifier(
    23/01,       //ICMP packets
    47/02,       //SYN
    47/12,       //SYN ACK
    47/10,       //ACK
    47/04,       //RST
    47/11,       //FIN ACK
    -);

// ==================
// element: s1_ip_classifier
// Description: Classify the HTTP packet to port 80
//
// 1. HTTP packets (TCP port 80) for further classification
// 2. Others dropped
// ==============

ip_classifier :: IPClassifier(
    tcp dst port 80,	// HTTP packets (TCP port 80)
    -);					//Others



// ==================
// Counter of ip classifier
// 1. ctr_icmp: ICMP packets
// 2. ctr_tcp_signaling: TCP signaling packets (SYN, SYN ACK, ACK, RST, FIN ACK)
// 2. ctr_http: http packets
// 3. ctr_ip_drop: Others
// =================
ctr_icmp :: Counter;
ctr_tcp_signaling :: Counter;
ctr_http :: Counter;
ctr_ip_drop :: Counter;

// ===== Level 3: HTTP payload =====

// ==================
// element: method_classifier
// Description: Classify the HTTP method
//
// 1. Offset 66: Ethernet header + IP header + TCP header
// 2. Classify PUT and POST methods
// 3. Others sent to insp
//
// Note:
// Strictly restrict method format as "POST" and "PUT",
// other irregular methot format likt "PoSt" will be dropped to INSP
// ==============

http_method_classifier :: Classifier(
	// Offset 66 (exp value): Ethernet header + IP header + TCP header
	64/504f5354,						// POST
   	64/505554,							// PUT
    64/474554,                          // GET
	64/48454144,                        // HEAD
	64/4f5054494f4e53, 					// OPTIONS
	64/5452414345, 						// TRACE
	64/44454c455445, 					// DELETE
	64/434f4e4e454354, 					// CONNECT
    -    
);

// Counter of ethernet classifier
ctr_post :: Counter;
ctr_put :: Counter;
ctr_get :: Counter;
ctr_head :: Counter;
ctr_options :: Counter;
ctr_trace :: Counter;
ctr_delete :: Counter;
ctr_connect :: Counter;



// Level 4: Injection in PUT method

ctr_pw :: Counter;
ctr_log :: Counter;
ctr_insert :: Counter;
ctr_update :: Counter;
ctr_pl_delete :: Counter;

// Search for the end of the HTTP header
search_payload :: Search("\r\n\r\n");
payload_check :: Classifier(
	// Offset 0: Pointer move to the end of the payload after search_payload
	0/636174202f6574632f706173737764,  // cat /etc/passwd
	0/636174202f7661722f6c6f672f,      // cat /var/log/
	0/494e53455254,                    // INSERT
	0/555044415445,                    // UPDATE
	0/44454c455445,                    // DELETE
	-
);


// ===== Data flow =====
// === From s1 ===
// Flow in from s1
fr_s1 -> rate_fr_s1 -> s1_ethernet_classifier;

// Level 1: Ethernet header
s1_ethernet_classifier[0] -> ctr_s1_arp -> to_lb1; // ARP forwarded to the output port
s1_ethernet_classifier[1] -> ctr_s1_ip -> s1_ip_classifier; // IPv4 packets for further classification
s1_ethernet_classifier[2] -> ctr_s1_ethernet_drop -> Discard; // Other Dropped

// Level 2: IP header + TCP header
s1_ip_classifier[0] -> Print("Is ICMP") -> ctr_icmp -> to_lb1; // ICMP forwarded to the output port
s1_ip_classifier[1, 2, 3, 4, 5] -> Print("Is TCP signaling") -> ctr_tcp_signaling -> to_lb1; // TCP signaling forwarded to the output port
s1_ip_classifier[6] -> Print ("Is HTTP") ->ip_classifier;

ip_classifier[0] -> Print("Is HTTP Port 80") -> ctr_http -> http_method_classifier; // HTTP packets for further classification
ip_classifier[1] -> Print("Is not port 80") -> ctr_ip_drop -> Discard; // Other dropped

// Level 3: HTTP payload
// HTTP payload for further classification
http_method_classifier[0] -> ctr_post -> to_lb1;
http_method_classifier[1] -> ctr_put -> search_payload; // PUT method for further classification
http_method_classifier[2] -> ctr_get -> to_insp; // GET method forwarded to the output port
http_method_classifier[3] -> ctr_head -> to_insp; // HEAD method forwarded to the output port
http_method_classifier[4] -> ctr_options -> to_insp; // OPTIONS method forwarded to the output port
http_method_classifier[5] -> ctr_trace -> to_insp; // TRACE method forwarded to the output port
http_method_classifier[6] -> ctr_delete -> to_insp; // DELETE method forwarded to the output port
http_method_classifier[7] -> ctr_connect -> to_insp; // CONNECT method forwarded to the output port
http_method_classifier[8] -> to_insp; // Other to insp

search_payload[0] -> payload_check; // Search for the end of the HTTP header
search_payload[1] -> to_insp; // Other to insp

payload_check[0] -> ctr_pw -> UnstripAnno() -> to_insp; 
payload_check[1] -> ctr_log -> UnstripAnno()-> to_insp; 
payload_check[2] -> ctr_insert -> UnstripAnno()-> to_insp; 
payload_check[3] -> ctr_update -> UnstripAnno()-> to_insp; 
payload_check[4] -> ctr_pl_delete -> UnstripAnno()-> to_insp; 
payload_check[5] -> UnstripAnno()-> to_lb1;

// ==== From lb1 ===
fr_lb1 -> rate_fr_lb1 -> lb1_ethernet_classifier;
lb1_ethernet_classifier[0] -> ctr_lb1_arp -> to_s1; // ARP forwarded to the output port
lb1_ethernet_classifier[1] -> ctr_lb1_ip -> to_s1;
lb1_ethernet_classifier[2] -> ctr_lb1_ethernet_drop -> Discard;


// Report output
DriverManager(
	pause,
    print > ./results/ids.report "
    ============================= IDS Report =============================
    Input Packet Rate (pps): $(add $(rate_fr_s1.rate) $(rate_fr_lb1.rate))
    Output Packet Rate (pps): $(add $(rate_to_s1.rate) $(rate_to_lb1.rate))

    Total # of input packets: $(add $(rate_fr_s1.count) $(rate_fr_lb1.count))
    Total # of output packets: $(add $(rate_to_s1.count) $(rate_to_lb1.count) $(rate_to_insp.count))

    ====================== Level 1: Ethernet header ======================
    Total # of ARP packets: $(add $(ctr_s1_arp.count) $(ctr_lb1_arp.count))
    Total # of IP packets: $(add $(ctr_s1_ip.count) $(ctr_lb1_ip.count))
    Total # of dropped packets (ethernet drop): $(add $(ctr_s1_ethernet_drop.count) $(ctr_lb1_ethernet_drop.count))

    =================== Level 2: IP + TCP header ====================
    Total # of ICMP packets: $(ctr_icmp.count)
    Total # of HTTP packets (TCP port 80): $(ctr_http.count)
    Total # of dropped packets (IP drop): $(ctr_ip_drop.count)

    =================== Level 3: HTTP payload ====================

    Total # of HTTP PUT packets: $(ctr_put.count)
    Total # of HTTP POST packets: $(ctr_post.count)
    Total # of HTTP GET packets: $(ctr_get.count)
    Total # of HTTP HEAD packets: $(ctr_head.count)
    Total # of HTTP OPTIONS packets: $(ctr_options.count)
    Total # of HTTP TRACE packets: $(ctr_trace.count)
    Total # of HTTP DELETE packets: $(ctr_delete.count)
    Total # of HTTP CONNECT packets: $(ctr_connect.count)

    =================== Level 4: HTTP payload ====================

    Total # of cat /etc/passwd Packets: $(ctr_pw.count)
    Total # of cat /var/log Packets: $(ctr_log.count)
    Total # of INSERT Packets: $(ctr_insert.count)
    Total # of UPDATE Packets: $(ctr_update.count)
    Total # of DELETE Packets: $(ctr_pl_delete.count)
    
    =================== Drop and suspicious packets ====================
    Total # of dropped packets: $(add $(ctr_s1_ethernet_drop.count) $(ctr_ip_drop.count) $(ctr_lb1_ethernet_drop.count))
    Packet Rate to INSP (pps): $(rate_to_insp.rate)
    Total # of packets to INSP: $(rate_to_insp.count)
    ",
    stop
    );
