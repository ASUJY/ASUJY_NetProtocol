//
// Created by asujy on 2026/1/19.
//

#include "protocol/ICMPPacket.h"
#include "protocol/IPPacket.h"
#include "protocol/EthernetPacket.h"
#include "log/Logger.h"
#include "Utils.h"
#include "machine.h"
#include "protocol/ARPPacket.h"

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

bool ICMPPacket::SendProtocolPacket(
    const Machine_t &localMachine, const Machine_t &targetMachine) {
    auto len = sizeof(struct ether_header_t) +
        sizeof(struct ip_header_t) + sizeof(struct icmp_header_t);
    std::unique_ptr<unsigned char[]> packet(new unsigned char[len]());
    if (!packet) {
        LOG_ERROR << "数据包缓冲区内存分配失败";
        return false;
    }
    ether_header_t etherHeader;
    memcpy(etherHeader.etherDHost , targetMachine.m_mac.get(), ETHER_ADDR_LEN);
    memcpy(etherHeader.etherSHost , localMachine.m_mac.get(), ETHER_ADDR_LEN);
    etherHeader.etherType = htons(ETHERTYPE_IP);

    IPPacket ipPacket;
    ipPacket.CreateProtocolHeader(localMachine, targetMachine,
        sizeof(ip_header_t) + sizeof(icmp_header_t), IP_PROTOCOL_ICMP);
    auto ipHeader = ipPacket.GetHeader();

    CreateProtocolHeader();

    memcpy(packet.get(), &etherHeader, sizeof(struct ether_header_t));
    memcpy(packet.get() + sizeof(struct ether_header_t),
        &ipHeader, sizeof(ip_header_t));
    memcpy(packet.get() + sizeof(struct ether_header_t) +
        sizeof(ip_header_t), &m_header, sizeof(icmp_header_t));

    int sent = pcap_sendpacket(localMachine.m_handler, packet.get(), len);
    if (sent < 0) {
        LOG_ERROR << "pcap_sendpacket failed: "
                    << pcap_geterr(localMachine.m_handler);
        return false;
    } else {
        LOG_INFO << "[success] sent ICMP request package......";
    }
    return true;
}

bool ICMPPacket::CreateProtocolHeader() {
    m_header.type = 8;
    m_header.code = 0;
    m_header.checksum = 0;
    m_header.identifier = htons(1);
    m_header.sequence_num = htons(1);
    m_header.checksum = IPChecksum(reinterpret_cast<uint16_t *>(&m_header),
        sizeof(icmp_header_t));
    return true;
}
