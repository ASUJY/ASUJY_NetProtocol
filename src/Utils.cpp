//
// Created by asujy on 2026/1/15.
//

#include "Utils.h"

#include <memory>
#include <pcap.h>
#include <iostream>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <cstring>

static void PcapifDeleter(pcap_if_t* ptr) {
    if (ptr != nullptr) {
        pcap_freealldevs(ptr);
    }
}

std::string GetNetDev(int index) {
    if (index < 0) {
        std::cerr << "Error: Invalid device index (" << index
                    << ") - index must be non-negative." << std::endl;
        std::exit(EXIT_FAILURE);
    }

    char errBuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t* allDevRaw = nullptr;
    if (pcap_findalldevs(&allDevRaw, errBuf) == -1) {
        std::cerr << "Error: pcap_findalldevs failed - " << errBuf << std::endl;
        std::exit(EXIT_FAILURE);
    }
    std::unique_ptr<pcap_if_t, decltype(PcapifDeleter)*> allDev(allDevRaw, PcapifDeleter);
    pcap_if_t* pdev = allDev.get();
    for (;pdev != nullptr && index > 0; pdev = pdev->next, --index);
    if (pdev == nullptr) {
        std::cerr << "Error: Device index (" << index
                    << ") out of range - no such network device." << std::endl;
        std::exit(EXIT_FAILURE);
    }
    if (pdev->name == nullptr) {
        std::cerr << "Error: Network device at index " << index
                    << " has no valid name." << std::endl;
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
        std::cerr << "Error: Invalid network interface name (null or empty)."
                    << std::endl;
        std::exit(EXIT_FAILURE); // C++11标准退出码
    }

    struct ifaddrs* ifapRaw = nullptr;
    if (getifaddrs(&ifapRaw) != 0) {
        std::cerr << "Error: getifaddrs failed - "
                    << std::strerror(errno) << std::endl;
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
        std::cerr << "Error: Failed to find IPv4 address for interface '"
                  << name << "'." << std::endl;
        std::exit(EXIT_FAILURE);
    }
    auto ip = sa->sin_addr.s_addr;
    return ip;
}

std::unique_ptr<unsigned char[]> GetLocalMac(const char* name) {
    std::unique_ptr<unsigned char[]> mac(new unsigned char[ETHER_ADDR_LEN]());
    if (!mac) {
        std::cerr << "Error: Failed to allocate memory for MAC address."
                    << std::endl;
        std::exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        std::cerr << "socket fail: " << std::strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
    }
    if (name == nullptr) {
        std::cerr << "Error: Network device name is null." << std::endl;
        std::exit(EXIT_FAILURE);
    }

    std::strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    // 获取mac地址
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        std::cerr << "ioctl fail: " << std::strerror(errno) << std::endl;
        close(fd);
        std::exit(EXIT_FAILURE);
    }
    std::memcpy(mac.get(), ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

    return mac;
}