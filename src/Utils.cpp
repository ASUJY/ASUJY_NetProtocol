//
// Created by asujy on 2026/1/15.
//

#include "Utils.h"
#include "log/Logger.h"

#include <memory>
#include <pcap.h>
#include <iostream>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <cstring>
#include <cassert>
#include <sstream>
#include <iomanip>
#include <netinet/ether.h>

static void PcapifDeleter(pcap_if_t* ptr) {
    if (ptr != nullptr) {
        pcap_freealldevs(ptr);
    }
}

std::string GetNetDev(int index) {
    if (index < 0) {
        LOG_ERROR << "Invalid device index (" << index
                    << ") - index must be non-negative.";
        std::exit(EXIT_FAILURE);
    }

    char errBuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t* allDevRaw = nullptr;
    if (pcap_findalldevs(&allDevRaw, errBuf) == -1) {
        LOG_ERROR << "pcap_findalldevs failed - " << errBuf;
        std::exit(EXIT_FAILURE);
    }
    std::unique_ptr<pcap_if_t, decltype(PcapifDeleter)*> allDev(allDevRaw, PcapifDeleter);
    pcap_if_t* pdev = allDev.get();
    for (;pdev != nullptr && index > 0; pdev = pdev->next, --index);
    if (pdev == nullptr) {
        LOG_ERROR << "Device index (" << index
                    << ") out of range - no such network device.";
        std::exit(EXIT_FAILURE);
    }
    if (pdev->name == nullptr) {
        LOG_ERROR << "Network device at index "
                    << index << " has no valid name.";
        std::exit(EXIT_FAILURE);
    }

    std::string ret(pdev->name);
    return ret;
}

static void IfaddrsDeleter(struct ifaddrs* ptr) {
    if (ptr != nullptr) {
        freeifaddrs(ptr);
    }
}

std::uint32_t GetLocalIP(const char* name) {
    if (name == nullptr || *name == '\0') {
        LOG_ERROR << "Invalid network interface name (null or empty).";
        std::exit(EXIT_FAILURE); // C++11标准退出码
    }

    struct ifaddrs* ifapRaw = nullptr;
    if (getifaddrs(&ifapRaw) != 0) {
        LOG_ERROR << "getifaddrs failed - " << std::strerror(errno);
        std::exit(EXIT_FAILURE);
    }
    std::unique_ptr<struct ifaddrs, decltype(IfaddrsDeleter)*> ifap(ifapRaw, IfaddrsDeleter);
    struct sockaddr_in *sa = nullptr;
    for (auto ifa = ifap.get(); ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr != nullptr &&
            ifa->ifa_addr->sa_family == AF_INET &&
            !strcmp(name, ifa->ifa_name)) {
            sa = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
            break;
        }
    }
    if (sa == nullptr) {
        LOG_ERROR << "Failed to find IPv4 address for interface '"
                  << name << "'.";
        std::exit(EXIT_FAILURE);
    }
    auto ip = sa->sin_addr.s_addr;
    return ip;
}

std::unique_ptr<unsigned char[]> GetLocalMac(const char* name) {
    std::unique_ptr<unsigned char[]> mac(new unsigned char[ETHER_ADDR_LEN]());
    if (!mac) {
        LOG_ERROR << "Failed to allocate memory for MAC address.";
        std::exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOG_ERROR << "socket fail: " << std::strerror(errno);
        std::exit(EXIT_FAILURE);
    }
    if (name == nullptr) {
        LOG_ERROR << "Network device name is null.";
        std::exit(EXIT_FAILURE);
    }

    std::strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    // 获取mac地址
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        LOG_ERROR << "ioctl fail: " << std::strerror(errno);
        close(fd);
        std::exit(EXIT_FAILURE);
    }
    std::memcpy(mac.get(), ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

    return mac;
}

void PrintMac(const char* msg, const unsigned char* mac) {
    assert(mac != nullptr && "MAC address pointer cannot be null");
    if (mac == nullptr) {
        LOG_ERROR << (msg ? msg : "Unknown message") << " - MAC pointer is null!";
        return;
    }

    std::ostringstream oss;
    oss << (msg ? msg : "MAC Address: ");
    oss << std::hex << std::setfill('0');

    for (std::size_t i = 0; i < ETH_ALEN; ++i) {
        oss << "0x" << std::setw(2) << static_cast<uint16_t>(mac[i]);
        if (i < 5) {
            oss << " ";
        }
    }
    LOG_INFO << oss.str();
}

void PrintIP(const char* msg, const in_addr ip) {
    char ipStr[INET_ADDRSTRLEN] = {0};
    if (inet_ntop(AF_INET, &ip, ipStr, INET_ADDRSTRLEN) == nullptr) {
        LOG_ERROR << "Failed to convert IP to string!";
    }
    LOG_INFO << msg << ipStr;
}

void PrintIP(const char* msg, const std::uint32_t ip) {
    char ipStr[INET_ADDRSTRLEN] = {0};
    if (inet_ntop(AF_INET, &ip, ipStr, INET_ADDRSTRLEN) == nullptr) {
        LOG_ERROR << "Failed to convert IP to string.";
    }
    LOG_INFO << msg << ipStr;
}

void PrintIP(const char* msg, const std::uint8_t ip[]) {
    LOG_INFO << msg << IPv4ToStr(ip);;
}

void Print2Hex(const std::string msg, std::uint16_t hex) {
    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(2) << std::hex << hex;
    LOG_INFO << msg << oss.str();
}

void Print4Hex(const std::string msg, std::uint16_t hex) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(4) << hex;
    LOG_INFO << msg << oss.str();
}

std::string IPv4ToStr(const std::uint8_t ip[4]) {
    std::stringstream oss;
    for (int i = 0; i < 4; ++i) {
        oss << static_cast<int>(ip[i]);
        if (i != 3) {
            oss << ".";
        }
    }
    return oss.str();
}

std::string IPv4ToStr(const uint32_t ip) {
    uint8_t ipv4[4] = {0};
    memcpy(ipv4, &ip, sizeof(uint32_t));
    return IPv4ToStr(ipv4);
}

std::string MacToStr(const std::uint8_t mac[ETH_ALEN], const std::string& sep) {
    std::stringstream oss;
    oss << std::hex << std::setfill('0') << std::uppercase;
    for (int i = 0; i < ETH_ALEN; ++i) {
        oss << std::setw(2) << static_cast<unsigned int>(mac[i]);
        if (i != ETH_ALEN - 1) {
            oss << sep;
        }
    }
    return oss.str();
}

std::unique_ptr<unsigned char[]> StrToMac(std::string mac, const char sep) {
    std::stringstream oss(mac);
    std::string tmp;
    int i = 0;
    std::unique_ptr<unsigned char[]> res(new unsigned char[6]);
    while (std::getline(oss, tmp, sep) && i < 6) {
        unsigned long val = strtoul(tmp.c_str(), nullptr, 16);
        res[i++] = static_cast<uint8_t>(val);
    }
    return res;
}

std::string GetBasename(const std::string &path) {
    std::string basename = path;
    auto lastSlash = basename.find_last_of("/");
    if (lastSlash != std::string::npos) {
        basename = basename.substr(lastSlash + 1);
    } else {
        basename = "";
    }
    return basename;
}

uint16_t IPChecksum(uint16_t *data, int length) {
    uint32_t sum = 0;

    while (length > 1) {
        sum += *data++;
        length -= 2;
    }

    if (length == 1) {
        sum += *((uint8_t*) data);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t) ~sum;
}