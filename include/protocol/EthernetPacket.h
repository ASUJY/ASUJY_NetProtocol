//
// Created by asujy on 2026/1/15.
//

#ifndef ETHERNETPACKET_H
#define ETHERNETPACKET_H

#include <netinet/ether.h>

/* 10Mb/s ethernet header */
struct ether_header_t
{
    uint8_t etherDHost[ETH_ALEN];    /* destination eth addr */
    uint8_t etherSHost[ETH_ALEN];    /* source ether addr */
    uint16_t etherType;              /* packet type ID field */
} __attribute__ ((__packed__));

class EthernetPacket {
public:
    EthernetPacket() = default;
    EthernetPacket(const EthernetPacket&) = default;
    EthernetPacket& operator=(const EthernetPacket&) = default;
    EthernetPacket(EthernetPacket&&) = default;
    EthernetPacket& operator=(EthernetPacket&&) = default;
    ~EthernetPacket() = default;

    bool ParseProtocolHeader(const unsigned char* packet);
private:
    ether_header_t m_header;
};

#endif //ETHERNETPACKET_H
