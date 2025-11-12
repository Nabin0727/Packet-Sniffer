// Program to capture the Network Packet
#include<stdio.h>
#include<stdlib.h>
#include<pcap/pcap.h>

// Call me function
void call_me(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packetd_ptr)
{
	printf("You just received a packet!\n");
}

// Main Function
int main( int argc, char const *argvc[])
{
	// Declaring the device name and error buffer size
	// PCAP_ERRBUF_SIZE is defined in pcah.h

	char *device = "ens192";
	char error_buffer[PCAP_ERRBUF_SIZE];

	// BUFSIZ is defined in stdio.h, 0 to disable promiscuous mode and -1 to diable timeout
	//

pcap_t *capdev = pcap_open_live(device, BUFSIZ, 0, -1, error_buffer);


// If capdev is null that means something went wrong, so we print the error which is stored in error_buffer and exit the program
//

if(capdev == NULL)
{
	printf("ERR: pcap_open_live() %s\n", error_buffer);
	exit(1);
}

// Let's limit the capture to 5 packets 
//

int packets_count = 5;

// pacp_loop retunrs 0 upon success and -1 if it fails, we listen to this return value and print and error if pcap_loop failed

if(pcap_loop( capdev, packets_count, call_me, (u_char*)NULL))
{
	printf("ERR: pcap_loop() failed!\n");
	exit(1);
}

	return 0;

}
