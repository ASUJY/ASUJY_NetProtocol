//
// Created by asujy on 2026/1/26.
//

#include "handler/Monitor.h"
#include <iostream>
#include <iomanip>
#include <thread>
#include <cstring>

std::atomic<uint64_t> Monitor::m_recvBytes{0};
std::atomic<uint64_t> Monitor::m_recvPackets{0};

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

void Monitor::DispTraffic() {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        uint64_t bytes = m_recvBytes.exchange(0);
        uint64_t packets = m_recvPackets.exchange(0);

        // 单位换算：B -> KB -> MB -> GB
        double speed = static_cast<double>(bytes);
        std::string unit = "B/s";
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

        std::cout << "\r\033[K" << std::fixed << std::setprecision(2)
                  << "实时流量: " << speed << " " << unit << " | "
                  << "数据包: " << packets << " 个/秒 | "
                  << "状态: 监控中" << std::flush;
    }
}

void Monitor::Process() {
    if (!m_pkthdr) {
        return;
    }
    m_recvBytes += m_pkthdr->len;
    m_recvPackets++;
}