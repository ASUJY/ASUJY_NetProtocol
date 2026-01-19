//
// Created by asujy on 2026/1/19.
//

#include "protocol/ICMPPacket.h"
#include "protocol/IPPacket.h"
#include "protocol/EthernetPacket.h"
#include "log/Logger.h"
#include "Utils.h"
#include <arpa/inet.h>

bool ICMPPacket::ParseProtocolHeader(const unsigned char *packet) {
    const icmp_header_t* icmp = reinterpret_cast<const icmp_header_t*>(packet +
        sizeof(struct ether_header_t) + sizeof(ip_header_t));
    m_header.type = icmp->type;
    m_header.code = icmp->code;
    m_header.checksum = icmp->checksum;
    m_header.identifier = icmp->identifier;
    m_header.sequence_num = icmp->sequence_num;
    PrintICMPHeader();
    return true;
}

void ICMPPacket::PrintICMPHeader() {
    LOG_INFO << "类型: " << static_cast<int>(m_header.type);
    LOG_INFO << "code: " << static_cast<int>(m_header.code);
    Print4Hex("checksum: 0x", htons(m_header.checksum));
    Print4Hex("identifier: 0x", htons(m_header.identifier));
    Print4Hex("sequence_num: 0x", htons(m_header.sequence_num));
}

