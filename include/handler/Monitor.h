//
// Created by asujy on 2026/1/26.
//

#ifndef MONITOR_H
#define MONITOR_H

#include <atomic>
#include <memory>
#include <pcap.h>

class Monitor {
public:
    Monitor() = default;
    Monitor(const struct pcap_pkthdr *pkthdr, const unsigned char *packet);
    ~Monitor() = default;
    void AddTraffic(uint64_t bytes, uint64_t packets);

    // 实时显示线程：每秒刷新一次数据
    static void DispTraffic();

    void Process();
private:
    static std::atomic<uint64_t> m_recvBytes;
    static std::atomic<uint64_t> m_recvPackets;
    static std::atomic<uint64_t> m_icmpBytes;
    static std::atomic<uint64_t> m_imcpPackets;
    static std::atomic<uint64_t> m_tcpBytes;
    static std::atomic<uint64_t> m_tcpPackets;
    static std::atomic<uint64_t> m_udpBytes;
    static std::atomic<uint64_t> m_udpPackets;
    std::unique_ptr<pcap_pkthdr> m_pkthdr;
    std::unique_ptr<unsigned char[]> m_packet;
};

void TrafficMonitor(unsigned char *userData, const struct pcap_pkthdr *pkthdr,
                        const unsigned char *packet);

#endif //MONITOR_H
