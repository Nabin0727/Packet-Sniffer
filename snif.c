// Program to capture the Network Packet
#include<stdio.h>
#include<stdlib.h>
#include<pcap/pcap.h>

//Global function to handel signal
static pcap_t *global_capdev = NULL;

// Call me function
void call_me(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packetd_ptr)
{
	printf("Captured Packet: length=%u\n", pkthdr->len);
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

	char *device = "ens192";
	char error_buffer[PCAP_ERRBUF_SIZE];
	int snaplen = BUFSIZ;
	int promisc = 0;
	int timeout_ms = 1000;

	// BUFSIZ is defined in stdio.h, 0 to disable promiscuous mode and -1 to diable timeout
	//

	// Override the device with user input
	if(arg > 1) device = argv[1];

	global_capdev= pcap_open_live(device, snaplen, promisc, timeout_ms, error_buffer);

	// If capdev is null that means something went wrong, so we print the error which is stored in error_buffer and exit
	// the program
	if(!global_capdev)
	{
		fprintf(stderr, "Error opening devices %s: %s\n", device, error_buffer);
		return 1;
	}

	// Let's limit the capture to 5 packets 
	//
	
	//int packets_count = 5;
	
	// Setup Ctrl + C
	struct sigactioin sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handle_sigint;
	sigaction(SIGINT, &sa, NULL);

	//Start capturing the packets 
	//pacp_loop retunrs 0 upon success and -1 if it fails, we listen to this return value and print and error if 
	// pcap_loop failed
	
	if(pcap_loop( global_capdev, -1, call_me, (u_char*)NULL))
	{
		printf("ERR: pcap_loop() failed!\n");
		exit(1);
	}

	// Closing 
	printf("\nCaptured finished. Closing device.\n");
	pcap_close(global_capdev);
	return 0;

}
