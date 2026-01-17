//
// Created by asujy on 2026/1/16.
//

#include "handler/PacketHandler.h"
#include "log/Logger.h"
#include "Utils.h"
#include "protocol/Protocol.h"
#include "protocol/EthernetPacket.h"
#include "protocol/ARPPacket.h"
#include "protocol/IPPacket.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>

/*
 * 每抓到一个包就会执行packet_handler
 * pkthdr: 数据包头部信息(时间戳、实际长度、捕获长度)
 * packet: 数据包的原始字节数据（包含链路层、网络层、传输层等所有数据）
 */
void PacketHandler(unsigned char *userData,
    const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    if (pkthdr == nullptr || packet == nullptr) {
        LOG_ERROR << "Invalid packet data (null pointer).";
        return;
    }

    // 检查数据包长度是否足够容纳以太网头
    if (pkthdr->len < ETHERNET_HEADER_LEN) {
        LOG_ERROR << "Packet too short (len=" << pkthdr->len
                  << ") to contain Ethernet header.";
        return;
    }

    Protocol<EthernetPacket, ether_header_t> etherProt;
    etherProt.ParseProtocolHeader(packet);
    auto protocolType = ntohs(etherProt.GetHeader().etherType);
    switch (protocolType) {
    case ETHERTYPE_ARP:
        PacketHandlerARP(packet);
        break;
    case IPV4_PROTOCOL:
        PacketHandlerIP(packet);
        break;
    }
}

void PacketHandlerARP(const unsigned char *packet) {
    Protocol<ARPPacket, arp_header_t> arpProt;
    arpProt.ParseProtocolHeader(packet);
}

void PacketHandlerIP(const unsigned char *packet) {
    Protocol<IPPacket, ip_header_t> ipProt;
    ipProt.ParseProtocolHeader(packet);
}