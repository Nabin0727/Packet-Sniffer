// Program to capture the Network Packet
#include<stdio.h>
#include<stdlib.h>
#include<pcap/pcap.h>
#include<stdlib.h>
#include<string.h>
#include<signal.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>

//Global function to handel signal
static pcap_t *global_capdev = NULL;

// Link header length 
int link_hdr_length = 0;


// Call me function
void call_me(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packetd_ptr)
{
	//printf("Captured Packet: length=%u\n", pkthdr->len);
	packetd_ptr += link_hdr_length;   // Move pointer past link-layer header (Ethernet = 14  bytes)

//	struct ip *ip_hdr = (struct ip*) packetd_ptr;
//
//	// inet_ntoa() writes it's result to an address and return this address, but subswquent calls to inet_ntoa() also 
//	// write to the same address so we need to copy the resut to a buffer.
//	char packet_srcip[INET_ADDRSTRLEN];
//	char packet_dstip[INET_ADDRSTRLEN];
//
//	 strcpy(packet_srcip, inet_ntoa(ip_hdr->ip_src)); // source ip address
//	 strcpy(packet_dstip, inet_ntoa(ip_hdr->ip_dst)); // destination ip address
//
//	 int packet_id = ntohs(ip_hdr -> ip_id), // identification 
//	     packet_ttl = ip_hdr -> ip_ttl,     // time to live 
//	     packet_tos = ip_hdr -> ip_tos,     // type of service
//	     packet_len = ntohs(ip_hdr -> ip_len), // header length + data length
//	     packet_hlen = ip_hdr -> ip_hl;      // header length

	// We will be using inet_ntop() instead of inet_ntoa()
	// Interpret remaining bytes as IPv4 header
	struct iphdr *ip_hdr = (struct iphdr*)packetd_ptr;

	char src_ip[INET_ADDRSTRLEN];
	char dst_ip[INET_ADDRSTRLEN];

	// Convert source and destination IP address to text
	inet_ntop(AF_INET, &(ip_hdr -> saddr), src_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ip_hdr -> daddr), dst_ip, INET_ADDRSTRLEN);

	// Extract fields (convert network -> host byter order where needed)
	
	int packet_id = ntohs(ip_hdr -> id);
	int packet_ttl = ip_hdr -> ttl;
	int packet_tos = ip_hdr -> tos;
	int packet_len = ntohs(ip_hdr -> tot_len);
	int packet_hlen = ip_hdr -> ihl *4; // ihl is in 32-bit words


	// Printing 
	printf("\n***********************************************\n");
	printf("ID: %d | SRC: %s | DST: %s | TOS: 0x%x | TTL: %d\n", packet_id, src_ip, dst_ip, packet_tos, packet_ttl);


	packetd_ptr += packet_hlen;
	int protocol_type = ip_hdr -> protocol;

	struct tcphdr *tcp_header;
	struct udphdr *udp_header;
	struct icmp *icmp_header;
	int src_port, dst_port;

	switch(protocol_type)
	{
		case IPPROTO_TCP:
			tcp_header = (struct tcphdr *)packetd_ptr;
			src_port = ntohs(tcp_header -> th_sport);
			dst_port = ntohs(tcp_header -> th_dport);
			printf("PROTO: TCP | FLAGS %c%c%c | SPORT: %d | DPORT: %d |\n",
					(tcp_header->th_flags & TH_SYN ? 'S' : '-'),
					(tcp_header->th_flags & TH_ACK ? 'A' : '-'),
					(tcp_header->th_flags & TH_URG ? 'U' : '-'),
					src_port, dst_port);
			break;
		
		case IPPROTO_UDP:
			udp_header = (struct udphdr*)packetd_ptr;
			src_port = ntohs(udp_header->uh_sport);
			dst_port = ntohs(udp_header->uh_dport);
			printf("PROTO: UDP | SPORT: %d | DPORT: %d |\n", src_port, dst_port);
			break;

		case IPPROTO_ICMP:
			icmp_header = (struct icmp *)packetd_ptr;
			int icmp_type = icmp_header->icmp_type;
			int icmp_type_code = icmp_header->icmp_code;
			printf("PROTO: ICMP | TYPE: %d | CODE %d |\n",icmp_type, icmp_type_code);
			break;
	}

}

// SIGINT handler
void handle_sigint(int sig)
{
	if(global_capdev != NULL)
	{
		pcap_breakloop(global_capdev);
	}
}

// Main Function
int main( int argc, char const *argvc[])
{
	// Declaring the device name and error buffer size
	// PCAP_ERRBUF_SIZE is defined in pcah.h

	char device[50] = "ens192";
	char error_buffer[PCAP_ERRBUF_SIZE];
	int snaplen = BUFSIZ;
	int promisc = 0;
	int timeout_ms = 1000;

	// BUFSIZ is defined in stdio.h, 0 to disable promiscuous mode and -1 to diable timeout
	//

	// Override the device with user input
	if(argc > 1) 
	{
		strncpy(device, argvc[1], (sizeof(device)));
		device[sizeof(device) - 1] = '\0';
	}

	global_capdev= pcap_open_live(device, snaplen, promisc, timeout_ms, error_buffer);

	// If capdev is null that means something went wrong, so we print the error which is stored in error_buffer and exit
	// the program
	if(!global_capdev)
	{
		fprintf(stderr, "Error opening devices %s: %s\n", device, error_buffer);
		return 1;
	}

	int data_link = pcap_datalink(global_capdev);

	switch(data_link)
	{
		case DLT_NULL:
			link_hdr_length = 4;
			break;

		case DLT_EN10MB:
			link_hdr_length = 14;
			break;

		default:
			link_hdr_length = 0;
	}

	// Let's limit the capture to 5 packets 
	//int packets_count = 5;
	
	// Setup Ctrl + C
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handle_sigint;
	sigaction(SIGINT, &sa, NULL);

	//Start capturing the packets 
	//pacp_loop retunrs 0 upon success and -1 if it fails, we listen to this return value and print and error if 
	// pcap_loop failed
	
	int flag = pcap_loop(global_capdev, -1, call_me, NULL);

	if(flag == -1)
	{
		fprintf(stderr, "ERR: pcap_loop() failed: %s\n", pcap_geterr(global_capdev));
		exit(1);
	}
	else if(flag == -2)
	{
		printf("\nCapture stopped by user (Ctrl+C).\n");
		exit(1);
	}

	// Closing 
	printf("\nCaptured finished. Closing device.\n");
	pcap_close(global_capdev);
	return 0;

}
