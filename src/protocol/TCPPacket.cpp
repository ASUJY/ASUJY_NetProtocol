//
// Created by asujy on 2026/1/19.
//

#include "protocol/TCPPacket.h"
#include "protocol/EthernetPacket.h"
#include "log/Logger.h"
#include "protocol/Protocol.h"
#include "protocol/IPPacket.h"
#include "Utils/Utils.h"
#include "machine.h"

bool TCPPacket::SendProtocolPacket(
        const Machine_t &localMachine, const Machine_t &targetMachine) {
    unsigned char tcpOptions[] = {
        0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0xaf, 0xef,
        0x15, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07
    };

    ether_header_t etherHeader;
    memcpy(etherHeader.etherDHost , targetMachine.m_mac.get(), ETHER_ADDR_LEN);
    memcpy(etherHeader.etherSHost , localMachine.m_mac.get(), ETHER_ADDR_LEN);
    etherHeader.etherType = htons(IPV4_PROTOCOL);

    IPPacket ipPacket;
    ipPacket.CreateProtocolHeader(localMachine, targetMachine,
        sizeof(ip_header_t) + sizeof(tcp_header_t) +
        sizeof(tcpOptions), IP_PROTOCOL_TCP);
    auto ipHeader = ipPacket.GetHeader();

    CreateProtocolHeader(localMachine, targetMachine, tcpOptions,
        sizeof(tcpOptions), NULL, 0);

    int packetLen = sizeof(struct ether_header) + sizeof(ip_header_t) +
            sizeof(tcp_header_t) + sizeof(tcpOptions);
    std::unique_ptr<unsigned char[]> packet(new unsigned char[packetLen]());
    memcpy(packet.get(), &etherHeader, sizeof(struct ether_header_t));
    memcpy(packet.get() + sizeof(struct ether_header_t),
        &ipHeader, sizeof(ip_header_t));
    memcpy(packet.get() + sizeof(struct ether_header_t) +
        sizeof(ip_header_t), &m_header, sizeof(tcp_header_t));
    memcpy(packet.get() + sizeof(struct ether_header_t) +
        sizeof(ip_header_t) + sizeof(tcp_header_t),
        tcpOptions, sizeof(tcpOptions));
    int sent = pcap_sendpacket(localMachine.m_handler, packet.get(), packetLen);
    if (sent < 0) {
        LOG_ERROR << "pcap_sendpacket failed: "
                    << pcap_geterr(localMachine.m_handler);
        return false;
    } else {
        LOG_INFO << "sent TCP SYN package......";
    }
    return true;
}

bool TCPPacket::SendProtocolPacketData(
        const Machine_t &localMachine, const Machine_t &targetMachine,
        char* data, size_t dataLen) {
    ether_header_t etherHeader;
    memcpy(etherHeader.etherDHost , targetMachine.m_mac.get(), ETHER_ADDR_LEN);
    memcpy(etherHeader.etherSHost , localMachine.m_mac.get(), ETHER_ADDR_LEN);
    etherHeader.etherType = htons(IPV4_PROTOCOL);

    IPPacket ipPacket;
    ipPacket.CreateProtocolHeader(localMachine, targetMachine,
        sizeof(ip_header_t) + sizeof(tcp_header_t) +
        dataLen, IP_PROTOCOL_TCP);
    auto ipHeader = ipPacket.GetHeader();

    CreateProtocolHeader(localMachine, targetMachine, nullptr,
        0, data, dataLen);

    int packetLen = sizeof(struct ether_header) + sizeof(ip_header_t) +
            sizeof(tcp_header_t) + dataLen;
    std::unique_ptr<unsigned char[]> packet(new unsigned char[packetLen]());
    memcpy(packet.get(), &etherHeader, sizeof(struct ether_header_t));
    memcpy(packet.get() + sizeof(struct ether_header_t),
        &ipHeader, sizeof(ip_header_t));
    memcpy(packet.get() + sizeof(struct ether_header_t) +
        sizeof(ip_header_t), &m_header, sizeof(tcp_header_t));
    memcpy(packet.get() + sizeof(struct ether_header_t) +
        sizeof(ip_header_t) + sizeof(tcp_header_t),
        data, dataLen);
    int sent = pcap_sendpacket(localMachine.m_handler, packet.get(), packetLen);
    if (sent < 0) {
        LOG_ERROR << "pcap_sendpacket failed: "
                    << pcap_geterr(localMachine.m_handler);
        return false;
    } else {
        LOG_INFO << "sent TCP data package......";
    }
    return true;
}

bool TCPPacket::CreateProtocolHeader(
    const Machine_t &localMachine, const Machine_t &targetMachine,
    u_char *options, size_t optionsLen, char *str, size_t strLen) {

    std::unique_ptr<pseudo_header_t> pseudo(new pseudo_header_t());
    pseudo->src_addr = localMachine.m_ip;
    pseudo->dest_addr = targetMachine.m_ip;
    pseudo->reserved = 0;
    pseudo->protocol = 6;
    pseudo->length = htons(sizeof(tcp_header_t) + optionsLen + strLen);

    m_header.source_port = htons(localMachine.m_port);
    m_header.dest_port = htons(targetMachine.m_port);
    m_header.data_offset = (sizeof(tcp_header_t) + optionsLen) / 4 << 4;  // tcp header + tcp options的长度
    m_header.window_size = htons(0xfaf0);
    m_header.checksum = 0;
    m_header.urgent_pointer = 0;
    auto checksum =
        TCPChecksum(reinterpret_cast<uint8_t*>(pseudo.get()),
            sizeof(pseudo_header_t),reinterpret_cast<uint8_t*>(&m_header),
        sizeof(tcp_header_t), options, optionsLen,
        reinterpret_cast<uint8_t*>(str), strLen);
    m_header.checksum = htons(checksum);
    return true;
}

bool TCPPacket::ParseProtocolHeader(const unsigned char *packet) {
    const tcp_header_t* tcp = reinterpret_cast<const tcp_header_t*> (packet +
        sizeof(struct ether_header_t) + sizeof(ip_header_t));
    m_header.source_port = tcp->source_port;
    m_header.dest_port = tcp->dest_port;
    m_header.sequence_num = tcp->sequence_num;
    m_header.ack_num = tcp->ack_num;
    m_header.data_offset = tcp->data_offset;
    m_header.flags = tcp->flags;
    m_header.window_size = tcp->window_size;
    m_header.checksum = tcp->checksum;
    m_header.urgent_pointer = tcp->urgent_pointer;
    PrintTCPHeader();
    return true;
}

void TCPPacket::PrintTCPHeader() {
    LOG_INFO << "===== tcp protocol =====";
    LOG_INFO << "source_port: " << htons(m_header.source_port);
    LOG_INFO << "dest_port: " << htons(m_header.dest_port);
    LOG_INFO << "sequence_num: " << htonl(m_header.sequence_num);
    LOG_INFO << "ack_num: " << htonl(m_header.ack_num);
    Print2Hex("data_offset: 0x", m_header.data_offset);
    Print2Hex("flags: 0x", m_header.flags);
    LOG_INFO << "window_size: " << htonl(m_header.window_size);
    Print4Hex("checksum: 0x", htons(m_header.checksum));
    Print4Hex("urgent_pointer: 0x", htons(m_header.urgent_pointer));
}
