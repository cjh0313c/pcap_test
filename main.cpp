#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

struct s_ethernet{
    u_int8_t dmac[6];
    u_int8_t smac[6];
    u_int8_t ethertype[2];
};

struct s_ip{
    u_int8_t ip_vhl;
    u_int8_t ip_tos;
    u_int16_t ip_tl;
    u_int16_t ip_iden;
    u_int16_t ip_ffo;
    u_int8_t ip_ttl;
    u_int8_t ip_proto;
    u_int16_t ip_chksum;
    u_int8_t ip_saddr[4];
    u_int8_t ip_daddr[4];
};

struct s_tcp{
    u_int8_t tcp_sport[2];
    u_int8_t tcp_dport[2];
    u_int32_t tcp_seqnum;
    u_int32_t tcp_acknum;
    u_int8_t tcp_offrev;
    u_int8_t tcp_flag;
    u_int16_t tcp_winsize;
    u_int16_t tcp_checksum;
    u_int16_t tcp_urp;
};
struct s_tcpdata{
    u_int8_t tcpdata[10]={"\0"};
};



void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac(u_int8_t*mac)
{
    for (int i=0;i<6;i++)
    {
        printf("%02x", mac[i]);
        if(i<5) printf(":");
    }
    printf("\n");
}

void print_ip(u_int8_t*ip)
{
    for(int i=0;i<4;i++)
    {
        printf("%d",ip[i]);
        if(i<3) printf(".");
    }
    printf("\n");
}

void print_tcp(uint8_t *port)
{
    printf("%d\n", (port[0]<<8)|port[1]);
}

void print_tcpdata(u_int8_t* tcpdata)
{

    printf("tcpdata: ");
    for(int i=0;i<10;i++)
    {
        if(tcpdata[i]=='\0') break;
        printf("%02x ", tcpdata[i]);
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    struct s_ethernet* ethernet;
    struct s_ip* ip;
    struct s_tcp* tcp;
    struct s_tcpdata* tcpd;

    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("============================\n");


    ethernet=(s_ethernet*)packet;

    printf("Smac: ");
    print_mac(ethernet->smac);
    printf("Dmac: ");
    print_mac(ethernet->dmac);


    if(((ethernet->ethertype[0])<<8|(ethernet->ethertype[1]))==0x0800){
        packet+=14;
        ip=(s_ip* )packet;
        printf("S-IP: ");
        print_ip(ip->ip_saddr);
        printf("D-IP: ");
        print_ip(ip->ip_daddr);

        if(ip->ip_proto==0x06) {

            int ip_hl=((ip->ip_vhl)&0x0f)*4;
            packet+=ip_hl;
            tcp=(s_tcp* )packet;
            printf("S-Port: ");
            print_tcp(tcp->tcp_sport);
            printf("D-Port: ");
            print_tcp(tcp->tcp_dport);

            int tcp_hl=((tcp->tcp_offrev)>>4)*4;

            if(tcp_hl<40)
            {
                packet+=tcp_hl;
                tcpd=(s_tcpdata* )packet;
                print_tcpdata(tcpd->tcpdata);
            }
             else continue;
        }
        else continue;
    }
  }
  pcap_close(handle);
  return 0;
}
