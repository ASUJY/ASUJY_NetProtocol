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
#include <sstream>
#include <iomanip>
#include <thread>
#include <cstring>
#include <dirent.h>
#include <unistd.h>

std::atomic<uint64_t> Monitor::m_recvBytes{0};
std::atomic<uint64_t> Monitor::m_recvPackets{0};
std::atomic<uint64_t> Monitor::m_icmpBytes{0};
std::atomic<uint64_t> Monitor::m_icmpPackets{0};
std::atomic<uint64_t> Monitor::m_tcpBytes{0};
std::atomic<uint64_t> Monitor::m_tcpPackets{0};
std::atomic<uint64_t> Monitor::m_udpBytes{0};
std::atomic<uint64_t> Monitor::m_udpPackets{0};
std::unordered_map<uint16_t, pid_t> Monitor::m_portToPID;
std::unordered_map<pid_t, ProcessTraffic> Monitor::m_pidToTraffic;
std::unordered_set<std::string> Monitor::m_processPorts;
std::mutex Monitor::m_mtx;

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
    std::lock_guard<std::mutex> locker(m_mtx);
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
        UpdatePortPIDMapping();
        std::lock_guard<std::mutex> locker(m_mtx);
        uint64_t bytes = m_recvBytes.exchange(0);
        uint64_t icmpBytes = m_icmpBytes.exchange(0);
        uint64_t tcpBytes = m_tcpBytes.exchange(0);
        uint64_t udpBytes = m_udpBytes.exchange(0);
        uint64_t packets = m_recvPackets.exchange(0);
        uint64_t icmpPackets = m_icmpPackets.exchange(0);
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

        system("clear");

        std::cout << std::fixed << std::setprecision(2)
                  << "实时流量: " << speed << " " << unit << " | "
                  << "数据包: " << packets << " 个/秒 | "
                  << "状态: 监控中" << std::endl;
        std::cout
                  << "TCP流量: " << tcpSpeed << " " << tcpUnit << " | "
                  << "数据包: " << tcpPackets << " 个/秒 | " << std::endl;
        std::cout
                  << "UDP流量: " << udpSpeed << " " << udpUnit << " | "
                  << "数据包: " << udpPackets << " 个/秒 | " << std::endl;
        std::cout
                  << "ICMP流量: " << icmpSpeed << " " << icmpUnit << " | "
                  << "数据包: " << icmpPackets << " 个/秒 | " << std::endl;

        std::cout << std::string(40, '=') << std::endl;
        std::cout << std::left  // 左对齐
                  << std::setw(15) << "进程名"
                  << std::setw(8)  << "PID"
                  << std::setw(12) << "发送字节"
                  << std::setw(12) << "接收字节" << std::endl;
        std::cout << std::string(40, '=') << std::endl;

        for (const auto& pair : m_pidToTraffic) {
            const auto& pid = pair.first;
            const auto& traffic = pair.second;

            std::cout << std::left
                      << std::setw(15) << traffic.name
                      << std::setw(8)  << pid
                      << std::setw(12) << traffic.sendBytes
                      << std::setw(12) << traffic.recvBytes << std::endl;
        }

        // 调整光标回退行数：原有4行 + 进程信息的行数（表头3行 + 进程数行）
        // 先回退到顶部，确保每次输出覆盖原有内容
        // 计算需要回退的总行数：4（原有流量行） + 3（进程表头） + m_pidToTraffic.size()（进程行）
        // int totalLines = 4 + 3 + static_cast<int>(m_pidToTraffic.size());
        // count = count > totalLines ? count : totalLines;
        // std::cout << "\033[" << count << "A\r" << std::flush;
        std::cout << std::flush;
    }
}

void Monitor::Process() {
    std::lock_guard<std::mutex> locker(m_mtx);
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
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    bool isOutgoing = false;
    Protocol<IPPacket, ip_header_t> ipProt;
    ipProt.ParseProtocolHeader(m_packet.get());
    switch (ipProt.GetHeader().protocol) {
        case IPPROTO_ICMP: {
            m_icmpBytes += m_pkthdr->len;
            m_icmpPackets++;
            // break;
            return;
        }
        case IPPROTO_TCP: {
            m_tcpBytes += m_pkthdr->len;
            m_tcpPackets++;
            Protocol<TCPPacket, tcp_header_t> tcpProt;
            tcpProt.ParseProtocolHeader(m_packet.get());
            srcPort = ntohs(tcpProt.GetHeader().source_port);
            dstPort = ntohs(tcpProt.GetHeader().dest_port);
            break;
        }
        case IPPROTO_UDP: {
            m_udpBytes += m_pkthdr->len;
            m_udpPackets++;
            return;
        }
        default:
            return;
            break;
    }

    pid_t pid = -1;
    if (m_portToPID.find(srcPort) != m_portToPID.end()) {
        pid = m_portToPID[srcPort];
        isOutgoing = true;  // 源端口是本地端口，属于发送流量
    } else if (m_portToPID.find(dstPort) != m_portToPID.end()) {
        pid = m_portToPID[dstPort];
        isOutgoing = false;
    }

    if (pid != -1) {
        if (isOutgoing) {
            m_pidToTraffic[pid].sendBytes += m_pkthdr->len;;
        } else {
            m_pidToTraffic[pid].recvBytes += m_pkthdr->len;;
        }
    }
}

void Monitor::PrintTrafficStats() {
    // system("clear");
    // std::cout << "============================================" << std::endl;
    // std::cout << "进程名\t\tPID\t发送字节\t接收字节" << std::endl;
    // std::cout << "============================================" << std::endl;
    //
    // for (const auto& pair : m_pidToTraffic) {
    //     const auto& pid = pair.first;
    //     const auto& traffic = pair.second;
    //
    //     std::cout << traffic.name << "\t\t"
    //               << pid << "\t"
    //               << traffic.sendBytes << "\t\t"
    //               << traffic.recvBytes << std::endl;
    // }
    // std::cout << std::flush;
}


static void DirDeleter(DIR* dir) {
    if (dir != nullptr) {
        closedir(dir);
    }
}

void Monitor::UpdatePortPIDMapping() {
    std::lock_guard<std::mutex> locker(m_mtx);
    m_portToPID.clear();
    m_processPorts.clear();

    // 遍历/proc下的所有进程
    std::string procPath = "/proc/";
    std::unique_ptr<DIR, decltype(DirDeleter)*> procDir(opendir(procPath.c_str()), DirDeleter);
    if (!procDir) {
        return;
    }

    dirent* entry;
    while ((entry = readdir(procDir.get())) != nullptr) {
        if (!isdigit(entry->d_name[0])) {
            continue;
        }
        std::string pidStr = entry->d_name;
        std::string fdPath = procPath + pidStr + "/fd/";
        std::unique_ptr<DIR, decltype(DirDeleter)*> fdDir(opendir(fdPath.c_str()), DirDeleter);
        if (!fdDir) {
            continue;
        }

        dirent* fdEntry;
        while ((fdEntry = readdir(fdDir.get())) != nullptr) {
            if (!isdigit(fdEntry->d_name[0])) {
                continue;
            }
            // 读取socket连接信息
            std::string linkPath = fdPath + fdEntry->d_name;
            char buf[256];
            ssize_t len = readlink(linkPath.c_str(), buf, sizeof(buf) - 1);
            if (len <= 0) {
                continue;
            }
            buf[len] = '\0';

            // 匹配IPv4 TCP/UDP socket
            if (strstr(buf, "socket:[") == nullptr) {
                continue;
            }

            // 读取端口信息
            std::string sockPath = "/proc/" + pidStr + "/net/tcp";
            std::ifstream sockFile(sockPath);
            std::string line;
            pid_t pid = std::stoi(pidStr);

            std::getline(sockFile, line);
            while (std::getline(sockFile, line)) {
                std::istringstream iss(line);
                std::string idx;
                std::string localAddr;
                std::string remAddr;
                std::string state;
                iss >> idx >> localAddr >> remAddr >> state;

                // 解析本地地址和端口（格式：0100007F:0050 -> 127.0.0.1:80）
                size_t colonPos = localAddr.find(":");
                if (colonPos == std::string::npos) {
                    continue;
                }
                std::string portHex = localAddr.substr(colonPos + 1);
                uint16_t port = std::stoi(portHex, nullptr, 16);
                m_portToPID[port] = pid;

                //获取进程名
                std::string commPath = "/proc/" + pidStr + "/comm";
                std::ifstream commFile(commPath);
                std::string procName;
                if (std::getline(commFile, procName)) {
                    m_pidToTraffic[pid].name = procName;
                    if (procName.compare("firefox") == 0) {
                        std::cout << "firefox:" << " pid " << pid << " port " << port << std::endl;
                    }
                }
            }

            // 处理UDP端口
            sockPath = "/proc/" + pidStr + "/net/udp";
            std::ifstream udpFile(sockPath);
            std::getline(udpFile, line); // 跳过表头
            while (std::getline(udpFile, line)) {
                std::istringstream iss(line);
                std::string idx;
                std::string localAddr;
                std::string remAddr;
                std::string state;
                iss >> idx >> localAddr >> remAddr >> state;

                size_t colonPos = localAddr.find(':');
                if (colonPos == std::string::npos) continue;

                std::string portHex = localAddr.substr(colonPos + 1);
                uint16_t port = std::stoi(portHex, nullptr, 16);
                m_portToPID[port] = pid;
            }
        }
    }
}


void TrafficMonitor(unsigned char *userData,
    const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    static ThreadPool<Monitor> pool;
    std::unique_ptr<Monitor> monitor(new Monitor(pkthdr, packet));
    pool.Append(std::move(monitor));
}