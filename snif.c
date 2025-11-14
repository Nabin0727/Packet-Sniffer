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

//Global function to handel signal
static pcap_t *global_capdev = NULL;

// Link header length 
int link_hdr_length = 0;


// Call me function
void call_me(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packetd_ptr)
{
	//printf("Captured Packet: length=%u\n", pkthdr->len);
	packetd_ptr += link_hdr_length;

	struct ip *ip_hdr = (struct ip*) packetd_ptr;

	// inet_ntoa() writes it's result to an address and return this address, but subswquent calls to inet_ntoa() also 
	// write to the same address so we need to copy the resut to a buffer.
	 char packet_srcip[INET_ADDRSTRLEN];
	 char packet_dstip[INET_ADDRSTRLEN];

	 strcpy(packet_srcip, inet_ntoa(ip_hdr->ip_src)); // source ip address
	 strcpy(packet_dstip, inet_ntoa(ip_hdr->ip_dst)); // destination ip address

	 int packet_id = ntohs(ip_hdr -> ip_id), // identification 
	     packet_ttl = ip_hdr -> ip_ttl,     // time to live 
	     packet_tos = ip_hdr -> ip_tos,     // type of service
	     packet_len = ntohs(ip_hdr -> ip_len), // header length + data length
	     packet_hlen = ip_hdr -> ip_hl;      // header length

	 // Printing 
	 printf("\n***********************************************\n");
	 printf("ID: %d | SRC: %s | DST: %s | TOS: 0x%x | TTL: %d\n", packet_id, packet_srcip, packet_dstip, packet_tos, packet_ttl);


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

	int link_hdr_type = pcap_datalink(global_capdev);

	switch(link_hdr_type)
	{
		case DLT_NULL:
			link_hdr_type = 4;
			break;

		case DLT_EN10MB:
			link_hdr_type = 14;
			break;

		default:
			link_hdr_type = 0;
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
	
	int flag = pacp_loop(global_capdev, -1, call_me, NULL);

	if(falg == -1)
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
