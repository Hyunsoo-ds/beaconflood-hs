#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>

struct BeaconFrame{
	short FrameControl;
	short Duration;
	u_char DestinationAddress[6];
	u_char SourceAddress[6];
	u_char BSSID[6];
	short Seq_ctl;
	long long int Timestamp;
	short BeaconInterval;
	short CapabilityInfo;
	u_char TagNumber;
	u_char SSIDLength;
	u_char SSID[20];
};

int main(int argc, char **argv)
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	struct BeaconFrame *frame;
	frame = malloc(sizeof(struct BeaconFrame));
	memset(frame,0, sizeof(struct BeaconFrame));

	//set BeaconFrame
	frame->FrameControl = 0x0008;
	frame->Duration = 0x0;
	memset(frame->DestinationAddress,0xff,sizeof(frame->DestinationAddress));

	strncpy(frame->SourceAddress, "abcdef", 6);
	strncpy(frame->BSSID, "abcdef", 6);

	frame->Seq_ctl = 0;
	frame->Timestamp = 12345678;
	frame->BeaconInterval= 0x0064; // 0.1second
	frame->CapabilityInfo = 0x0411;
	frame->TagNumber = 0; // SSID tag number
			
			
	strcpy(frame->SSID, "Hello World");
	frame->SSIDLength = strlen(frame->SSID);



	if(argc >=2){
		handle = pcap_open_live(argv[1], BUFSIZ,1, 1000, errbuf);

		if(!handle){
			fprintf(stderr,"\n Error occured while opening the adapter");
			return 0;
		}

	    while(1){

		    if (pcap_sendpacket(handle,frame, sizeof(struct BeaconFrame)) != 0)
		    {
			fprintf(stderr,"\nError sending the packet: %s \n", pcap_geterr(handle));
			return 0;
		    }
		    printf("packet Sended!\n");
		    usleep(100000);
	    }

	}
	else{
		printf("Put interface name where you want to flood in argv!\n");
	}

	return 0;
}
