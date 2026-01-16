//
// Created by asujy on 2026/1/16.
//

#ifndef PACKETHANDLER_H
#define PACKETHANDLER_H

#include <pcap.h>
#include <string>

constexpr std::uint16_t ETHERNET_HEADER_LEN = 14;  // 以太网帧头长度
constexpr std::uint8_t MIN_IP_HEADER_LEN = 5;      // IP头最小长度（单位：4字节）
constexpr std::uint8_t IP_VERSION_4 = 4;           // IPv4版本标识

void PacketHandler(unsigned char *userData, const struct pcap_pkthdr *pkthdr,
                        const unsigned char *packet);
void PacketHandlerARP(const unsigned char *packet);

#endif //PACKETHANDLER_H
