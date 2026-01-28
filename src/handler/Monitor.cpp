//
// Created by asujy on 2026/1/26.
//

#include "handler/Monitor.h"
#include "threadUtils/ThreadPool.h"
#include "protocol/Protocol.h"
#include "protocol/EthernetPacket.h"
#include "protocol/IPPacket.h"
#include "protocol/TCPPacket.h"

#include <iostream>
#include <iomanip>
#include <thread>
#include <cstring>

std::atomic<uint64_t> Monitor::m_recvBytes{0};
std::atomic<uint64_t> Monitor::m_recvPackets{0};
std::atomic<uint64_t> Monitor::m_icmpBytes{0};
std::atomic<uint64_t> Monitor::m_imcpPackets{0};
std::atomic<uint64_t> Monitor::m_tcpBytes{0};
std::atomic<uint64_t> Monitor::m_tcpPackets{0};
std::atomic<uint64_t> Monitor::m_udpBytes{0};
std::atomic<uint64_t> Monitor::m_udpPackets{0};

Monitor::Monitor(const pcap_pkthdr *pkthdr, const unsigned char *packet) {
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

void Monitor::AddTraffic(uint64_t bytes, uint64_t packets) {
    m_recvBytes += bytes;
    m_recvPackets += packets;
}

static void TrafficChange(uint64_t bytes, double &speed, std::string& unit) {
    // 单位换算：B -> KB -> MB -> GB
    speed = static_cast<double>(bytes);
    unit = "B/s";
    if (speed >= 1024) {
        speed /= 1024;
        unit = "KB/s";
    }
    if (speed >= 1024) {
        speed /= 1024;
        unit = "MB/s";
    }
    if (speed >= 1024) {
        speed /= 1024;
        unit = "GB/s";
    }
}

void Monitor::DispTraffic() {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        uint64_t bytes = m_recvBytes.exchange(0);
        uint64_t icmpBytes = m_icmpBytes.exchange(0);
        uint64_t tcpBytes = m_tcpBytes.exchange(0);
        uint64_t udpBytes = m_udpBytes.exchange(0);
        uint64_t packets = m_recvPackets.exchange(0);
        uint64_t icmpPackets = m_imcpPackets.exchange(0);
        uint64_t tcpPackets = m_tcpPackets.exchange(0);
        uint64_t udpPackets = m_udpPackets.exchange(0);
        double speed{0};
        double icmpSpeed{0};
        double tcpSpeed{0};
        double udpSpeed{0};
        std::string unit;
        std::string icmpUnit;
        std::string tcpUnit;
        std::string udpUnit;
        TrafficChange(bytes, speed, unit);
        TrafficChange(icmpBytes, icmpSpeed, icmpUnit);
        TrafficChange(tcpBytes, tcpSpeed, tcpUnit);
        TrafficChange(udpBytes, udpSpeed, udpUnit);
        std::cout << "\033[K" << std::fixed << std::setprecision(2)
                  << "实时流量: " << speed << " " << unit << " | "
                  << "数据包: " << packets << " 个/秒 | "
                  << "状态: 监控中" << std::endl;
        std::cout << "\033[K" << std::fixed << std::setprecision(2)
                  << "TCP流量: " << tcpSpeed << " " << tcpUnit << " | "
                  << "数据包: " << tcpPackets << " 个/秒 | " << std::endl;
        std::cout << "\033[K" << std::fixed << std::setprecision(2)
                  << "UDP流量: " << udpSpeed << " " << udpUnit << " | "
                  << "数据包: " << udpPackets << " 个/秒 | " << std::endl;
        std::cout << "\033[K" << std::fixed << std::setprecision(2)
                  << "ICMP流量: " << icmpSpeed << " " << icmpUnit << " | "
                  << "数据包: " << icmpPackets << " 个/秒 | " << std::endl;
        std::cout << "\033[4A\r" << std::flush;
    }
}

void Monitor::Process() {
    if (!m_pkthdr) {
        return;
    }
    m_recvBytes += m_pkthdr->len;
    m_recvPackets++;
    Protocol<EthernetPacket, ether_header_t> etherProt;
    etherProt.ParseProtocolHeader(m_packet.get());
    auto protocolType = ntohs(etherProt.GetHeader().etherType);
    if (protocolType != ETHERTYPE_IP) {
        return;
    }
    Protocol<IPPacket, ip_header_t> ipProt;
    ipProt.ParseProtocolHeader(m_packet.get());
    switch (ipProt.GetHeader().protocol) {
        case IPPROTO_ICMP: {
            m_icmpBytes += m_pkthdr->len;
            m_imcpPackets++;
            break;
        }
        case IPPROTO_TCP: {
            m_tcpBytes += m_pkthdr->len;
            m_tcpPackets++;
            break;
        }
        case IPPROTO_UDP: {
            m_udpBytes += m_pkthdr->len;
            m_udpPackets++;
        }
        default:
            break;
    }
}

void TrafficMonitor(unsigned char *userData,
    const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    static ThreadPool<Monitor> pool;
    std::unique_ptr<Monitor> monitor(new Monitor(pkthdr, packet));
    pool.Append(std::move(monitor));
}