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
#include <map>
#include <unordered_set>
#include <vector>

struct ProcessTraffic {
    std::string name;
    std::string type;
    pid_t pid;
    std::vector<std::pair<uint16_t, std::string>> ports; // 端口号和协议
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

    void Process();
private:
    static void UpdatePortPIDMapping();
    static void GetProcessInfo();
    static void GetSocketInfo();
    static void GetProcessPorts();
    std::vector<pid_t> findPidsUsingPortLinear(uint16_t port);
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

    static std::map<pid_t, ProcessTraffic> m_pidToTraffic;
    static std::unordered_map<ino_t, std::pair<uint16_t, std::string>> m_socketMap;
    static std::mutex m_mtx;

};

void TrafficMonitor(unsigned char *userData, const struct pcap_pkthdr *pkthdr,
                        const unsigned char *packet);

#endif //MONITOR_H
