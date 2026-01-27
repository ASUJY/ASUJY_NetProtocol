//
// Created by asujy on 2026/1/16.
//

#include "handler/PacketHandler.h"
#include "log/Logger.h"
#include "Utils/Utils.h"
#include "protocol/Protocol.h"
#include "protocol/EthernetPacket.h"
#include "protocol/ARPPacket.h"
#include "protocol/IPPacket.h"
#include "protocol/ICMPPacket.h"
#include "protocol/TCPPacket.h"
#include "handler/Monitor.h"
#include "threadUtils/ThreadPool.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <iostream>
#include <thread>
#include <iomanip>

PacketHandler::PacketHandler(const Machine_t &localMachine,
    const Machine_t &targetMachine, const pcap_pkthdr *pkthdr,
    const unsigned char *packet) :
        m_localMachine(localMachine), m_targetMachine(targetMachine) {
    if (pkthdr == nullptr || packet == nullptr) {
        throw std::invalid_argument("pkthdr or packet pointer is null");
    }
    if (pkthdr->len == 0 || pkthdr->len > 65535) {
        throw std::out_of_range("invalid packet length: " +
            std::to_string(pkthdr->len));
    }
    m_pkthdr = std::unique_ptr<pcap_pkthdr>(new pcap_pkthdr);
    std::memcpy(m_pkthdr.get(), pkthdr, sizeof(pcap_pkthdr));
    m_packet = std::unique_ptr<unsigned char[]>(new unsigned char[pkthdr->len]);
    std::memcpy(m_packet.get(), packet, pkthdr->len);
}

void PacketHandler::PacketHandlerARP() {
    Protocol<ARPPacket, arp_header_t> arpProt;
    arpProt.ParseProtocolHeader(m_packet.get());
}

void PacketHandler::PacketHandlerIP() {
    Protocol<IPPacket, ip_header_t> ipProt;
    ipProt.ParseProtocolHeader(m_packet.get());
    // 非发往本机的数据包不进行处理
    if (ipProt.GetHeader().dst_ip != m_localMachine.m_ip) {
        return;
    }

    switch (ipProt.GetHeader().protocol) {
    case IP_PROTOCOL_ICMP:
        PacketHandlerICMP();
        break;
    case IP_PROTOCOL_TCP:
        PacketHandlerTCP();
        break;
    default:
        LOG_WARN << "未做处理的协议类型: " << ipProt.GetHeader().protocol;
        break;
    }
}

void PacketHandler::PacketHandlerICMP() {
    Protocol<ICMPPacket, icmp_header_t> icmpProt;
    icmpProt.ParseProtocolHeader(m_packet.get());
}

void PacketHandler::PacketHandlerTCP() {
    Protocol<TCPPacket, tcp_header_t> tcpProt;
    tcpProt.ParseProtocolHeader(m_packet.get());

    std::string targetIP(IPv4ToStr(m_targetMachine.m_ip));
    auto isTrue = ARPPacket::IsContainsKey(IPv4ToStr(m_targetMachine.m_ip));
    if (!isTrue) {
        return;
    }
    std::vector<std::string> ret;
    if (ARPPacket::GetResultSetElement(IPv4ToStr(m_targetMachine.m_ip), ret)) {
        m_targetMachine.m_mac = StrToMac(ret[1]);
    }

    switch (tcpProt.GetHeader().flags) {
        case TCP_SYN_ACK: {
            uint32_t ackNum = ntohl(tcpProt.GetHeader().ack_num);
            uint32_t sequenceNum = ntohl(tcpProt.GetHeader().sequence_num);
            tcpProt.SetFlag(TCP_ACK);
            tcpProt.SetAckNum(htonl(sequenceNum + 1));
            tcpProt.SetSeqNum(htonl(ackNum));
            tcpProt.SendProtocolPacket(m_localMachine, m_targetMachine);
        }
        case TCP_ACK: {
            char data[100] = {0};
            std::cout << "发送给服务器的数据：";
            fgets(data, 100, stdin);
            uint32_t ackNum = ntohl(tcpProt.GetHeader().ack_num);
            uint32_t sequenceNum = ntohl(tcpProt.GetHeader().sequence_num);
            tcpProt.SetFlag(TCP_PSH_ACK);
            tcpProt.SetAckNum(htonl(sequenceNum));
            tcpProt.SetSeqNum(htonl(ackNum));
            tcpProt.SendProtocolPacketData(
                m_localMachine, m_targetMachine, data, strlen(data));
            break;
        }
        default: {
            Print2Hex("未作处理的数据包类型: ", tcpProt.GetHeader().flags);
            break;
        }
    }
}

void PacketHandler::Process() {
    Protocol<EthernetPacket, ether_header_t> etherProt;
    etherProt.ParseProtocolHeader(m_packet.get());
    auto protocolType = ntohs(etherProt.GetHeader().etherType);
    switch (protocolType) {
    case ETHERTYPE_ARP:
        PacketHandlerARP();
        break;
    case IPV4_PROTOCOL:
        PacketHandlerIP();
        break;
    }
}

/*
 * 每抓到一个包就会执行packet_handler
 * pkthdr: 数据包头部信息(时间戳、实际长度、捕获长度)
 * packet: 数据包的原始字节数据（包含链路层、网络层、传输层等所有数据）
 */
void Handler(unsigned char *userData,
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

    static ThreadPool<PacketHandler> pool;
    Machine_t* machine = reinterpret_cast<Machine_t*>(userData);
    std::unique_ptr<PacketHandler> phandler(new PacketHandler(
        machine[0], machine[1], pkthdr, packet));
    pool.Append(std::move(phandler));
}