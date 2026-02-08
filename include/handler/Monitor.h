//
// Created by asujy on 2026/1/26.
//

#ifndef MONITOR_H
#define MONITOR_H

#include <atomic>
#include <memory>
#include <mutex>
#include <pcap.h>
#include <unordered_map>
#include <unordered_set>

struct ProcessTraffic {
    std::string name;
    std::string type;
    uint16_t sendBytes = 0;
    uint16_t recvBytes = 0;
};

class Monitor {
public:
    Monitor() = default;
    Monitor(const struct pcap_pkthdr *pkthdr, const unsigned char *packet);
    ~Monitor() = default;
    void AddTraffic(uint64_t bytes, uint64_t packets);

    // 实时显示线程：每秒刷新一次数据
    static void DispTraffic();

    static void PrintTrafficStats();

    void Process();
private:
    static void InitTerminalDisplay();
    static void UpdatePortPIDMapping();
private:
    static std::atomic<uint64_t> m_recvBytes;
    static std::atomic<uint64_t> m_recvPackets;
    static std::atomic<uint64_t> m_icmpBytes;
    static std::atomic<uint64_t> m_icmpPackets;
    static std::atomic<uint64_t> m_tcpBytes;
    static std::atomic<uint64_t> m_tcpPackets;
    static std::atomic<uint64_t> m_udpBytes;
    static std::atomic<uint64_t> m_udpPackets;
    std::unique_ptr<pcap_pkthdr> m_pkthdr;
    std::unique_ptr<unsigned char[]> m_packet;
    static std::unordered_map<uint16_t, pid_t> m_portToPID;
    static std::unordered_map<pid_t, ProcessTraffic> m_pidToTraffic;
    static std::unordered_set<std::string> m_processPorts;
    static std::mutex m_mtx;

};

void TrafficMonitor(unsigned char *userData, const struct pcap_pkthdr *pkthdr,
                        const unsigned char *packet);

#endif //MONITOR_H
