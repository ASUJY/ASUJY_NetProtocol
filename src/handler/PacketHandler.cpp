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
#include "protocol/ICMPPacket.h"
#include "protocol/TCPPacket.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <iostream>

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
        PacketHandlerIP(userData, packet);
        break;
    }
}

void PacketHandlerARP(const unsigned char *packet) {
    Protocol<ARPPacket, arp_header_t> arpProt;
    arpProt.ParseProtocolHeader(packet);
}

void PacketHandlerIP(unsigned char *userData, const unsigned char *packet) {
    Protocol<IPPacket, ip_header_t> ipProt;
    ipProt.ParseProtocolHeader(packet);
    Machine_t* machine = reinterpret_cast<Machine_t*>(userData);
    // 非发往本机的数据包不进行处理
    if (ipProt.GetHeader().dst_ip != machine[0].m_ip) {
        return;
    }

    switch (ipProt.GetHeader().protocol) {
    case IP_PROTOCOL_ICMP:
        PacketHandlerICMP(packet);
        break;
    case IP_PROTOCOL_TCP:
        PacketHandlerTCP(userData, packet);
        break;
    default:
        LOG_WARN << "未做处理的协议类型: " << ipProt.GetHeader().protocol;
        break;
    }
}

void PacketHandlerICMP(const unsigned char *packet) {
    Protocol<ICMPPacket, icmp_header_t> icmpProt;
    icmpProt.ParseProtocolHeader(packet);
}

void PacketHandlerTCP(unsigned char *userData, const unsigned char *packet) {
    Protocol<TCPPacket, tcp_header_t> tcpProt;
    tcpProt.ParseProtocolHeader(packet);
    Machine_t* machine = reinterpret_cast<Machine_t*>(userData);

    std::string targetIP(IPv4ToStr(machine[1].m_ip));
    auto iter = ARPPacket::m_resultSet.find(IPv4ToStr(machine[1].m_ip));
    machine[1].m_mac = StrToMac(iter->second[1]);

    switch (tcpProt.GetHeader().flags) {
        case TCP_SYN_ACK: {
            uint32_t ackNum = ntohl(tcpProt.GetHeader().ack_num);
            uint32_t sequenceNum = ntohl(tcpProt.GetHeader().sequence_num);
            tcpProt.SetFlag(TCP_ACK);
            tcpProt.SetAckNum(htonl(sequenceNum + 1));
            tcpProt.SetSeqNum(htonl(ackNum));
            tcpProt.SendProtocolPacket(machine[0], machine[1]);
        }
        case TCP_ACK: {
            std::cout << "发送给服务器的数据：";
            break;
        }
        default: {
            Print2Hex("未作处理的数据包类型: ", tcpProt.GetHeader().flags);
            break;
        }
    }
}
