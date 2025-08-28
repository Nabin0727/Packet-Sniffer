#include<stdio.h>
#include<pcap.h>

int main()
{
	char *dev = "eth0"; // interface
	
	char errbuf[PACP_ERRBUF_SIZE];

	pcap_t *handel;

	struct pcap_pkthdr header;

	const u_char *packet;

	// open interface
	handel = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	
	if(handel == NULL)
	{
		fprintf(stderr, "Couldn't open devices %s: %s\n", dev, errbuf);
		return 2;
	}

	printf("Capturing packet on %s........\n", dev);


	pcap_close(handel);
	return 0;
}
