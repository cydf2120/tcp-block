// https://gitlab.com/gilgil/g/-/blob/master/src/net/pdu/gtcphdr.h
#pragma once

#include "iphdr.h"

// ----------------------------------------------------------------------------
// GTcpHdr
// ----------------------------------------------------------------------------
#pragma pack(push, 1)
struct TcpHdr final {
	uint16_t sport_;
	uint16_t dport_;
	uint32_t seq_;
	uint32_t ack_;
	uint8_t off_rsvd_;
	uint8_t flags_;
	uint16_t win_;
	uint16_t sum_;
	uint16_t urp_;

	uint16_t sport() { return ntohs(sport_); }
	uint16_t dport() { return ntohs(dport_); }
	uint32_t seq() { return ntohl(seq_); }
	uint32_t ack() { return ntohl(ack_); }
	uint8_t off() { return (off_rsvd_ & 0xF0) >> 4; }
	uint8_t rsvd() { return off_rsvd_ & 0x0F; }
	uint8_t flags() { return flags_; }
	uint16_t win() { return ntohs(win_); }
	uint16_t sum() { return ntohs(sum_); }
	uint16_t urp() { return ntohs(urp_); }

	// Flag(flag_)
	enum: uint8_t {
		Urg = 0x20,
		Ack = 0x10,
		Psh = 0x08,
		Rst = 0x04,
		Syn = 0x02,
		Fin = 0x01
	};

	static uint16_t calcChecksum(IpHdr* ipHdr, TcpHdr* tcpHdr);
	static char *parseData(TcpHdr* tcpHdr);
    static uint16_t parseDataLen(IpHdr* ipHdr, TcpHdr* tcpHdr);
};
typedef TcpHdr *PTcpHdr;
#pragma pack(pop)
