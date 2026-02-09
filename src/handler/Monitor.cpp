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
#include <algorithm>

std::atomic<uint64_t> Monitor::m_recvBytes{0};
std::atomic<uint64_t> Monitor::m_recvPackets{0};
std::atomic<uint64_t> Monitor::m_icmpBytes{0};
std::atomic<uint64_t> Monitor::m_icmpPackets{0};
std::atomic<uint64_t> Monitor::m_tcpBytes{0};
std::atomic<uint64_t> Monitor::m_tcpPackets{0};
std::atomic<uint64_t> Monitor::m_udpBytes{0};
std::atomic<uint64_t> Monitor::m_udpPackets{0};
std::map<pid_t, ProcessTraffic> Monitor::m_pidToTraffic;
std::unordered_map<ino_t, std::pair<uint16_t, std::string>> Monitor::m_socketMap;
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
    UpdatePortPIDMapping();
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
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
        << "数据包: " << packets << " 个/秒 | " << "状态: 监控中" << std::endl;
        std::cout << "TCP流量: " << tcpSpeed << " " << tcpUnit << " | "
                  << "数据包: " << tcpPackets << " 个/秒 | " << std::endl;
        std::cout << "UDP流量: " << udpSpeed << " " << udpUnit << " | "
                  << "数据包: " << udpPackets << " 个/秒 | " << std::endl;
        std::cout << "ICMP流量: " << icmpSpeed << " " << icmpUnit << " | "
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
            if (!traffic.ports.empty()) {
                std::cout << std::left
                      << std::setw(15) << traffic.name
                      << std::setw(8)  << pid
                      << std::setw(12) << traffic.sendBytes
                      << std::setw(12) << traffic.recvBytes << std::endl;
            }
        }
        std::cout << std::flush;
    }
}

void Monitor::Process() {
    // std::lock_guard<std::mutex> locker(m_mtx);
    if (!m_pkthdr) {
        return;
    }
    {
        std::lock_guard<std::mutex> locker(m_mtx);
        m_recvBytes += m_pkthdr->len;
        m_recvPackets++;
    }

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
            std::lock_guard<std::mutex> locker(m_mtx);
            m_icmpBytes += m_pkthdr->len;
            m_icmpPackets++;
            // break;
            return;
        }
        case IPPROTO_TCP: {
            std::lock_guard<std::mutex> locker(m_mtx);
            m_tcpBytes += m_pkthdr->len;
            m_tcpPackets++;
            Protocol<TCPPacket, tcp_header_t> tcpProt;
            tcpProt.ParseProtocolHeader(m_packet.get());
            srcPort = ntohs(tcpProt.GetHeader().source_port);
            dstPort = ntohs(tcpProt.GetHeader().dest_port);
            break;
        }
        case IPPROTO_UDP: {
            std::lock_guard<std::mutex> locker(m_mtx);
            m_udpBytes += m_pkthdr->len;
            m_udpPackets++;
            return;
        }
        default:
            return;
            break;
    }

    pid_t pid = -1;
    auto srcPortRes = findPidsUsingPortLinear(srcPort);
    auto dstPortRes = findPidsUsingPortLinear(dstPort);
    if (!srcPortRes.empty()) {
        pid = srcPortRes[0];
        isOutgoing = true;  // 源端口是本地端口，属于发送流量
    } else if (!dstPortRes.empty()) {
        pid = dstPortRes[0];
        isOutgoing = false;
    }



    if (pid != -1) {
        if (isOutgoing) {
            std::lock_guard<std::mutex> locker(m_mtx);
            m_pidToTraffic[pid].sendBytes += m_pkthdr->len;;
            auto temp = m_pidToTraffic[pid].sendBytes;
            int i = 0;
        } else {
            std::lock_guard<std::mutex> locker(m_mtx);
            m_pidToTraffic[pid].recvBytes += m_pkthdr->len;;
        }
    }
}

std::vector<pid_t> Monitor::findPidsUsingPortLinear(uint16_t port) {

    std::vector<pid_t> result;

    for (const auto& pair : m_pidToTraffic) {
        const ProcessTraffic& info = pair.second;

        // 使用std::find_if搜索端口
        auto it = std::find_if(
            info.ports.begin(),
            info.ports.end(),
            [port](const std::pair<uint16_t, std::string>& portInfo) {
                return portInfo.first == port;
            });

        if (it != info.ports.end()) {
            result.push_back(info.pid);
        }
    }

    return result;
}

static void DirDeleter(DIR* dir) {
    if (dir != nullptr) {
        closedir(dir);
    }
}

void Monitor::GetProcessInfo() {
    std::unique_ptr<DIR, decltype(DirDeleter)*> procDir(
        opendir("/proc"), DirDeleter);
    if (!procDir) {
        return;
    }

    struct dirent* entry = nullptr;
    while ((entry = readdir(procDir.get())) != nullptr) {
        if (entry->d_type == DT_DIR) {
            char* endptr = nullptr;
            pid_t pid = strtol(entry->d_name, &endptr, 10);
            if (*endptr == '\0' && pid > 0) {
                ProcessTraffic info;
                info.pid = pid;

                // 读取进程名
                std::string commPath = "/proc/" + std::to_string(pid) + "/comm";
                std::ifstream commFile(commPath);
                if (commFile) {
                    std::getline(commFile, info.name);
                    // 移除可能的换行符
                    if (!info.name.empty() && info.name.back() == '\n') {
                        info.name.pop_back();
                    }
                } else {
                    // 如果comm文件不存在，尝试从cmdline获取
                    std::string cmdlinePath = "/proc/" + std::to_string(pid) + "/cmdline";
                    std::ifstream cmdlineFile(cmdlinePath);
                    if (cmdlineFile) {
                        std::getline(cmdlineFile, info.name);
                        // 提取可执行文件名（去掉路径）
                        size_t lastSlash = info.name.find_last_of('/');
                        if (lastSlash != std::string::npos) {
                            info.name = info.name.substr(lastSlash + 1);
                        }
                        // 去掉参数部分（如果有）
                        size_t nullChar = info.name.find('\0');
                        if (nullChar != std::string::npos) {
                            info.name = info.name.substr(0, nullChar);
                        }
                    } else {
                        info.name = "unknown";
                    }
                }
                std::lock_guard<std::mutex> locker(m_mtx);
                m_pidToTraffic[pid] = info;
            }
        }
    }
}

// 将十六进制字符串转换为整数
uint32_t hexToDec(const std::string& hexStr) {
    uint32_t result = 0;
    for (char c : hexStr) {
        result *= 16;
        if (c >= '0' && c <= '9') {
            result += c - '0';
        } else if (c >= 'A' && c <= 'F') {
            result += c - 'A' + 10;
        } else if (c >= 'a' && c <= 'f') {
            result += c - 'a' + 10;
        }
    }
    return result;
}

void Monitor::GetSocketInfo() {
    std::vector<std::pair<std::string, std::string>> netFiles = {
        {"/proc/net/tcp", "tcp"},
        {"/proc/net/tcp6", "tcp6"},
        {"/proc/net/udp", "udp"},
        {"/proc/net/udp6", "udp6"}
    };

    for (const auto& fileInfo : netFiles) {
        std::ifstream netFile(fileInfo.first);
        if (!netFile) {
            continue;
        }

        std::string line;
        std::getline(netFile, line); // 跳过标题行
        while (std::getline(netFile, line)) {
            if (line.empty()) continue;
            std::istringstream iss(line);
            std::vector<std::string> tokens;
            std::string token;

            while (std::getline(iss, token, ' ')) {
                if (!token.empty()) {
                    tokens.push_back(token);
                }
            }

            if (tokens.size() < 10) continue;

            // 本地地址是tokens[1]（在sl之后）
            // 格式: 0100007F:0277
            std::string localAddr = tokens[1];
            size_t colonPos = localAddr.find(':');
            if (colonPos == std::string::npos) continue;

            std::string portHex = localAddr.substr(colonPos + 1);
            uint16_t port = hexToDec(portHex);

            // inode是tokens[9]（在/proc/net/tcp中）
            ino_t inode = 0;
            if (tokens.size() > 9) {
                for (size_t i = 9; i < tokens.size(); i++) {
                    char* endptr = nullptr;
                    ino_t val = strtoul(tokens[i].c_str(), &endptr, 10);
                    if (*endptr == '\0' && val > 0) {
                        inode = val;
                        break;
                    }
                }
            }
            if (inode > 0) {
                std::lock_guard<std::mutex> locker(m_mtx);
                m_socketMap[inode] = std::make_pair(port, fileInfo.second);
            }
        }
        netFile.close();
    }
}

void Monitor::GetProcessPorts() {
    std::lock_guard<std::mutex> locker(m_mtx);
    for (auto& pair : m_pidToTraffic) {
        std::string fdPath = "/proc/" + std::to_string(pair.second.pid) + "/fd";
        std::unique_ptr<DIR, decltype(DirDeleter)*> fdDir(opendir(
            fdPath.c_str()), DirDeleter);
        if (!fdDir) continue;

        struct dirent* fdEntry;
        while ((fdEntry = readdir(fdDir.get())) != nullptr) {
            std::string fdName = fdEntry->d_name;
            if (fdName == "." || fdName == "..") continue;
            std::string linkPath = fdPath + "/" + fdName;
            char linkTarget[1024];
            ssize_t len = readlink(linkPath.c_str(), linkTarget, sizeof(linkTarget) - 1);
            if (len == -1) continue;

            linkTarget[len] = '\0';
            std::string target(linkTarget);

            if (target.find("socket:[") != std::string::npos) {
                // 提取inode号
                size_t start = target.find('[') + 1;
                size_t end = target.find(']');
                if (start < end) {
                    std::string inodeStr = target.substr(start, end - start);
                    char* endptr = nullptr;
                    ino_t inode = strtoul(inodeStr.c_str(), &endptr, 10);
                    if (*endptr == '\0' && inode > 0) {
                        auto it = m_socketMap.find(inode);
                        if (it != m_socketMap.end()) {
                            // 判断是否已经添加该端口
                            bool found = false;
                            for (const auto& portInfo  : pair.second.ports) {
                                if (portInfo.first == it->second.first) {
                                    found = true;
                                    break;
                                }
                            }
                            if (!found) {
                                pair.second.ports.push_back(it->second);
                            }
                        }
                    }
                }
            }
        }
    }
}

void Monitor::UpdatePortPIDMapping() {
    // 获取pid和进程名
    GetProcessInfo();
    // 从/proc/net/tcp和/proc/net/udp获取socket信息
    GetSocketInfo();
    // 获取进程和端口的映射关系
    GetProcessPorts();
}


void TrafficMonitor(unsigned char *userData,
    const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    static ThreadPool<Monitor> pool;
    std::unique_ptr<Monitor> monitor(new Monitor(pkthdr, packet));
    pool.Append(std::move(monitor));
}