//
// Created by asujy on 2026/1/16.
//

#include "protocol/ARPPacket.h"
#include "protocol/EthernetPacket.h"
#include "Utils.h"

#include <memory>
#include <arpa/inet.h>

bool ARPPacket::ParseProtocolHeader(const unsigned char *packet) {
    const arp_header_t* arp =
        reinterpret_cast<const arp_header_t*>(packet + sizeof(ether_header_t));
    m_header.hrd = arp->hrd;
    m_header.prot = arp->prot;
    m_header.hln = arp->hln;
    m_header.pln = arp->pln;
    m_header.op = arp->op;
    std::copy(arp->sha, arp->sha + ETH_ALEN, m_header.sha);
    std::copy(arp->spa, arp->spa + IP_LEN, m_header.spa);
    std::copy(arp->tha, arp->tha + ETH_ALEN, m_header.tha);
    std::copy(arp->tpa, arp->tpa + IP_LEN, m_header.tpa);
    PrintARPHeader();
    return true;
}

void ARPPacket::PrintARPHeader() {
    Print4Hex("ARP: hardware_type: 0x", htons(m_header.hrd));
    Print4Hex("ARP: protocol_type: 0x", htons(m_header.prot));
    Print2Hex("ARP: hlen: 0x", m_header.hln);
    Print2Hex("ARP: plen: 0x", m_header.pln);
    Print4Hex("ARP: opcode: 0x", htons(m_header.op));
    PrintMac("ARP: sender_mac: ", m_header.sha);
    PrintIP("ARP: sender_ip: ", m_header.spa);
    PrintMac("ARP: target_mac: ", m_header.tha);
    PrintIP("ARP: sender_ip: ", m_header.tpa);
}

