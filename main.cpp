#include <cstdio>
#include <iostream>
#include <pcap.h>
#include <unistd.h>
#include <error.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

#define MSG "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n"

#pragma pack(push, 1)
struct EthIpTcpPacket final {
	EthHdr eth_;
	IpHdr ip_;
	TcpHdr tcp_;
};
#pragma pack(pop)

void usage() 
{
	printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

Mac find_my_mac(char* dev)
{	
	struct ifreq 	ifr;
	Mac 			my_mac;
	int 			fd;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	memset(&ifr, 0, sizeof(ifr)); 
	strcpy(ifr.ifr_name, dev); 

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
	{
		perror("ioctl");
		exit(-1);
	} 
	close(fd);

	my_mac = Mac((uint8_t *)ifr.ifr_hwaddr.sa_data); 

	return my_mac;
}

int send_forward_packet(pcap_t* handle, EthIpTcpPacket* packet, Mac my_mac)
{
	EthIpTcpPacket forward_packet;

	memcpy(&forward_packet, packet, sizeof(EthIpTcpPacket));
	forward_packet.eth_.smac_ = my_mac;

	forward_packet.ip_.len_ = htons(sizeof(EthIpTcpPacket) - sizeof(EthHdr));
	forward_packet.ip_.sum_ = 0;
	forward_packet.ip_.sum_ = IpHdr::calcChecksum(&forward_packet.ip_);

	forward_packet.tcp_.seq_ = htonl(packet->tcp_.seq() + TcpHdr::parseDataLen(&packet->ip_, &packet->tcp_));
	forward_packet.tcp_.flags_ = TcpHdr::Rst | TcpHdr::Ack;
	forward_packet.tcp_.off_rsvd_ = (sizeof(TcpHdr) / 4) << 4;
	forward_packet.tcp_.sum_ = 0;
	forward_packet.tcp_.sum_ = TcpHdr::calcChecksum(&forward_packet.ip_, &forward_packet.tcp_);

	return pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&forward_packet), sizeof(EthIpTcpPacket));
}

int send_backward_packet(pcap_t* handle, EthIpTcpPacket* packet, Mac my_mac)
{
	struct {
		EthIpTcpPacket backward_packet;
		char msg[sizeof(MSG)];
	} p;
		
	memcpy(&p.backward_packet, packet, sizeof(EthIpTcpPacket));
	p.backward_packet.eth_.smac_ = my_mac;
	p.backward_packet.eth_.dmac_ = packet->eth_.smac_;

	p.backward_packet.ip_.len_ = htons(sizeof(EthIpTcpPacket) - sizeof(EthHdr) + sizeof(MSG));
	p.backward_packet.ip_.ttl_ = 128;
	p.backward_packet.ip_.sip_ = packet->ip_.dip_;
	p.backward_packet.ip_.dip_ = packet->ip_.sip_;
	p.backward_packet.ip_.sum_ = 0;
	p.backward_packet.ip_.sum_ = IpHdr::calcChecksum(&p.backward_packet.ip_);

	p.backward_packet.tcp_.seq_ = packet->tcp_.ack_;
	p.backward_packet.tcp_.ack_ = htonl(packet->tcp_.seq() + TcpHdr::parseDataLen(&packet->ip_, &packet->tcp_));
	p.backward_packet.tcp_.sport_ = packet->tcp_.dport_;
	p.backward_packet.tcp_.dport_ = packet->tcp_.sport_;
	p.backward_packet.tcp_.flags_ = TcpHdr::Fin | TcpHdr::Ack | TcpHdr::Psh;
	p.backward_packet.tcp_.off_rsvd_ = (sizeof(TcpHdr) / 4) << 4;
	p.backward_packet.tcp_.sum_ = 0;
	memcpy(&p.msg, MSG, sizeof(MSG));

	p.backward_packet.tcp_.sum_ = TcpHdr::calcChecksum(&p.backward_packet.ip_, &p.backward_packet.tcp_);

	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (fd < 0)
		return -1;

	int optval = 1;
	setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int));

	struct sockaddr_in sockaddr;
	sockaddr.sin_port = htons(p.backward_packet.tcp_.dport());
	sockaddr.sin_family = AF_INET;
	sendto(fd, &p.backward_packet.ip_, sizeof(IpHdr) + sizeof(TcpHdr) + sizeof(MSG), 0, reinterpret_cast<const struct sockaddr*>(&sockaddr), sizeof(sockaddr));
	close(fd);
	return 0;
	// return pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&p), sizeof(p));
}

int main(int argc, char* argv[]) 
{
	char* 	dev = argv[1];
	char*	pattern = argv[2];
	char 	errbuf[PCAP_ERRBUF_SIZE];
	Mac		my_mac;
	struct {
		EthIpTcpPacket eit_packet;
		char tcp_data[BUFSIZ];
	} p;
	
	if (argc < 3) 
	{
		usage();
		return -1;
	}

	my_mac = find_my_mac(dev);

	std::cout << "my MAC: " << std::string(my_mac) << std::endl;

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) 
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	while (true) 
	{
		pcap_pkthdr*	header;
		const u_char*	packet;
		char* data;
		int	res = pcap_next_ex(handle, &header, &packet);
		if (res == 0)
			continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
			continue;
		
		if (header->len < sizeof(EthHdr))
			continue;
		
		memcpy(&p.eit_packet, packet, header->len);
		if (p.eit_packet.eth_.type() != EthHdr::Ip4)
			continue;

		if (p.eit_packet.ip_.p() != IpHdr::Tcp)
			continue;
		
		data = TcpHdr::parseData(&p.eit_packet.tcp_);
		if (strstr(data, pattern) == NULL)
			continue;
		
		std::cout << "block!" << std::endl;
		send_forward_packet(handle, &p.eit_packet, my_mac);
		send_backward_packet(handle, &p.eit_packet, my_mac);
	}	

	return 0;
}