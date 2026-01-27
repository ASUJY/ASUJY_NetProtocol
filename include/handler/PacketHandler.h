//
// Created by asujy on 2026/1/16.
//

#ifndef PACKETHANDLER_H
#define PACKETHANDLER_H

#include "machine.h"
#include <memory>
#include <pcap.h>

constexpr std::uint16_t ETHERNET_HEADER_LEN = 14;  // 以太网帧头长度
constexpr std::uint8_t MIN_IP_HEADER_LEN = 5;      // IP头最小长度（单位：4字节）
constexpr std::uint8_t IP_VERSION_4 = 4;           // IPv4版本标识

class PacketHandler {
public:
    PacketHandler() = delete;
    PacketHandler(const Machine_t &localMachine, const Machine_t &targetMachine,
        const struct pcap_pkthdr *pkthdr, const unsigned char *packet);
    PacketHandler(const PacketHandler&) = delete;
    PacketHandler& operator=(const PacketHandler&) = delete;
    PacketHandler(PacketHandler&&) = default;
    PacketHandler& operator=(PacketHandler&&) = default;
    ~PacketHandler() = default;

    void Process();
private:
    void PacketHandlerARP();
    void PacketHandlerIP();
    void PacketHandlerICMP();
    void PacketHandlerTCP();
private:
    Machine_t m_localMachine{};
    Machine_t m_targetMachine{};
    std::unique_ptr<pcap_pkthdr> m_pkthdr;
    std::unique_ptr<unsigned char[]> m_packet;
};

void Handler(unsigned char *userData,
    const struct pcap_pkthdr *pkthdr, const unsigned char *packet);

#endif //PACKETHANDLER_H
