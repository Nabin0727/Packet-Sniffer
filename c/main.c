// writing simple packet capture in c

#include<stdio.h>
#include<pcap.h>

// packet capture handeler function
void packet_handler(u_char *dump_handel, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("\n=== Packet Captured ===\n");
    printf("Packet length: %d bytes\n", header->len);
    printf("Captured length: %d bytes\n", header->caplen);
    printf("Timestamp: %ld.%06ld\n", header->ts.tv_sec, header->ts.tv_usec);

    // Print first 16 bytes
    printf("First 16 bytes: ");
    for (int i = 0; i < 16 && i < header->caplen; i++) {
        printf("%02x ", packet[i]);
    }
    printf("\n");
	// dumping captured packet
    pcap_dump(dump_handel, header, packet);
}

int main()
{
	char *dev = "eth0"; // interface
	
	char errbuf[PCAP_ERRBUF_SIZE];

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

	// open dump file
	pcap_dumper_t *dumper = pcap_dump_open(handel, "capture.pcap");
	if(dumper == NULL){
		fprintf(stderr, "couldnot open dump");
		return 2;
	}

	printf("Capturing packet on %s........\n", dev);
	
	pcap_loop(handel, 10, packet_handler, (u_char *)dumper);

	pcap_close(handel);
	pcap_dump_close(dumper);
	return 0;
}
