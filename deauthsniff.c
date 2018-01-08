#include<stdio.h> 
#include<stdlib.h> 
#include<pcap.h> 
#include<netinet/in.h> 

void usage(void); 
void pcapHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
int deauthcount = 0;

int main(int argc, char ** argv){ 
	
	if(argc >= 2){ 
		int offset = 0;
		char *erbuf; 
		char *dev; 
	        dev = argv[1]; 
		pcap_t *handle;
		handle = pcap_open_live(dev, BUFSIZ, 0, 3000, erbuf);
		if(handle==NULL){ printf("ERROR: %s\n",erbuf); exit(1); }
		
		char *filter = "type mgt subtype deauth"; // deauth frame 
		struct bpf_program fp; 
		bpf_u_int32 netp; 
		if(pcap_compile(handle,&fp,filter,0,netp)==-1) 
			fprintf(stderr,"Error compiling Libpcap filter, %s\n",filter);
		if(pcap_setfilter(handle,&fp)==-1) 
			fprintf(stderr,"Error setting Libpcap filter, %s\n",filter); 

		pcap_loop(handle, 0, pcapHandler, NULL); 
	
		return 0; 
	}else{ 
		usage();
		return 1;
	}
}

void pcapHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	struct radiotap_header{ 
		uint8_t it_rev; 
		uint8_t it_pad; 
		uint16_t it_len;
	};
	
	deauthcount += 1;
	const u_char *bssid; 
	const u_char *essid; 
	const u_char *essidLen;
	const u_char *channel; 
	const u_char *rssi;
	int offset = 0;
	struct radiotap_header *rtaphdr;
	rtaphdr = (struct radiotap_header *) packet;
	offset = rtaphdr->it_len;
	bssid = packet + 42; 
	essid = packet + 64; 
	essidLen = packet + 63;
	rssi = packet + 22; 
	signed int rssiDbm = rssi[0] - 256;
	channel = packet + 18;
	int channelFreq = channel[1] * 256 + channel[0];
	char *ssid = malloc(63);
	unsigned int i = 0; 
	while(essid[i] > 0x1){
		ssid[i] = essid[i]; 
		i++; 
	}
	ssid[i] = '\0'; 
	fprintf(stdout, "Deauth frame found!\n");
	fprintf(stdout,"AP Frequency: %iMhz\n",channelFreq);
	fprintf(stdout, "%d deauthentication frames found!", deauthcount);
	fprintf(stdout,"\n");

	if(deauthcount>=10) {
	fprintf(stdout, "It is possible that somebody is trying to perform a deauthentication attack. \
Please switch to a wired connection or move to a different location.\n");
	fprintf(stdout, "\n");	
}
	
	pcap_dumper_t *outputFile;
	pcap_t *fileHandle;
	char *outputFileName = "output.cap";
	fileHandle = pcap_open_dead(DLT_IEEE802_11_RADIO, BUFSIZ);
	outputFile = pcap_dump_open(fileHandle,outputFileName);
	pcap_dump((u_char *) outputFile,header, packet);
	pcap_close(fileHandle);

	return;
}

void usage(void){ // display how to use application
	fprintf(stderr,"Usage: sudo ./deauthsniff deviceName\n"); 
	return; 
}
