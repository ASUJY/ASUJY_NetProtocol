//
// Created by asujy on 2026/1/15.
//

#include <string>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "machine.h"
#include "Utils.h"
#include "log/Logger.h"
#include "protocol/Protocol.h"
#include "protocol/EthernetPacket.h"


constexpr std::uint16_t ETHERNET_HEADER_LEN = 14;  // 以太网帧头长度
constexpr std::uint8_t MIN_IP_HEADER_LEN = 5;      // IP头最小长度（单位：4字节）
constexpr std::uint8_t IP_VERSION_4 = 4;           // IPv4版本标识

/*
 * 每抓到一个包就会执行packet_handler
 * pkthdr: 数据包头部信息(时间戳、实际长度、捕获长度)
 * packet: 数据包的原始字节数据（包含链路层、网络层、传输层等所有数据）
 */
void PacketHandler(u_char *userData,
    const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    if (pkthdr == nullptr || packet == nullptr) {
        LOG_ERROR << "Invalid packet data (null pointer).";
        return;
    }

    // 检查数据包长度是否足够容纳以太网头（避免越界访问）
    if (pkthdr->len < ETHERNET_HEADER_LEN) {
        LOG_ERROR << "Packet too short (len=" << pkthdr->len
                  << ") to contain Ethernet header.";
        return;
    }

    // 获取IP header和TCP header的位置
    const struct ip *ipHeader = reinterpret_cast<const struct ip*>(
        packet + ETHERNET_HEADER_LEN);
    // 检查IP版本（仅处理IPv4）
    if (ipHeader->ip_v != IP_VERSION_4) {
        LOG_WARN << "Non-IPv4 packet detected (version="
                    << static_cast<int>(ipHeader->ip_v) << "), skipped.";
        return;
    }
    // 检查IP头长度合法性（ip_hl单位是4字节，需≥5且≤15）
    if (ipHeader->ip_hl < MIN_IP_HEADER_LEN || ipHeader->ip_hl > 15) {
        LOG_ERROR << "Invalid IP header length (ip_hl="
                    << static_cast<int>(ipHeader->ip_hl) << "), skipped.";
        return;
    }
    const std::uint16_t ipHeaderLen = ipHeader->ip_hl * 4;  // 转换为字节数
    // 检查数据包长度是否足够容纳IP头
    if (pkthdr->len < ETHERNET_HEADER_LEN + ipHeaderLen) {
        LOG_ERROR << "Packet too short (len=" << pkthdr->len
                  << ") to contain IP header (need="
                  << ETHERNET_HEADER_LEN + ipHeaderLen << ").";
        return;
    }

    const struct tcphdr *tcpHeader = reinterpret_cast<const struct tcphdr *>(
        packet + ETHERNET_HEADER_LEN + ipHeaderLen);
    // 检查数据包长度是否足够容纳TCP头（TCP头最小20字节）
    if (pkthdr->len <
        ETHERNET_HEADER_LEN + ipHeaderLen + sizeof(struct tcphdr)) {
        LOG_ERROR << "Packet too short (len=" << pkthdr->len
                  << ") to contain TCP header, skipped.";
        return;
    }

    // 转换端口号（网络字节序转主机字节序）
    const std::uint16_t srcPort = ntohs(tcpHeader->source);
    const std::uint16_t dstPort = ntohs(tcpHeader->dest);

    // 输出信息
    PrintIP("Source IP: ", ipHeader->ip_src);
    PrintIP("Destination IP: ", ipHeader->ip_dst);
    LOG_INFO << "Source port: " << static_cast<int>(srcPort);
    LOG_INFO << "Destination port: " << static_cast<int>(dstPort);

    Protocol<EthernetPacket> etherProt;
    etherProt.ParseProtocolHeader(packet);
}

static void PcapDeleter(pcap_t* ptr) {
    if (ptr != nullptr) {
        pcap_close(ptr);
    }
}

int main()
{
    Logger::Config("NetProtocol.log");
    Machine_t localMachine;
    localMachine.m_device = GetNetDev(0);
    localMachine.m_ip = GetLocalIP(localMachine.m_device.c_str());
    localMachine.m_mac = GetLocalMac(localMachine.m_device.c_str());
    LOG_INFO << localMachine.m_device;
    PrintIP("LOCAL IP: ", localMachine.m_ip);
    PrintMac("LOCAL MAC: ", localMachine.m_mac.get());

    // 打开网络设备
    char errBuf[PCAP_ERRBUF_SIZE] = {0};
    auto handlerRaw =
        pcap_open_live(localMachine.m_device.c_str(), BUFSIZ, 1, 1000, errBuf);
    if (handlerRaw == nullptr) {
        LOG_ERROR << "Couldn't open device '" << localMachine.m_device
                  << "' - " << errBuf;
        return EXIT_FAILURE;
    }

    // 抓包处理
    std::unique_ptr<pcap_t, decltype(PcapDeleter)*> handler(handlerRaw, PcapDeleter);
    int ret = pcap_loop(handler.get(), 0, PacketHandler, nullptr);
    if (ret == -1) {
        LOG_ERROR << "pcap_loop failed - " << pcap_geterr(handler.get());
        return EXIT_FAILURE;
    } else if (ret == -2) {
        LOG_ERROR << "pcap_loop was interrupted (normal exit).";
        return EXIT_FAILURE;
    }

    return 0;
}