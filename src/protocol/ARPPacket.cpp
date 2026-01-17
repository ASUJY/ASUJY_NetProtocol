//
// Created by asujy on 2026/1/16.
//

#include "protocol/ARPPacket.h"
#include "protocol/EthernetPacket.h"
#include "Utils.h"
#include "log/Logger.h"
#include "machine.h"
#include "protocol/Protocol.h"

#include <memory>
#include <pcap.h>

extern Machine_t g_localMachine;
ARPPacket::ResultSet ARPPacket::m_resultSet{};

bool ARPPacket::ParseProtocolHeader(const unsigned char *packet) {
    const arp_header_t* arp =
        reinterpret_cast<const arp_header_t*>(packet + sizeof(ether_header_t));

    std::copy(arp->tpa, arp->tpa + IP_LEN, m_header.tpa);
    std::copy(arp->tha, arp->tha + ETH_ALEN, m_header.tha);
    std::string tpa(IPv4ToStr(m_header.tpa));
    std::string tha(MacToStr(m_header.tha));
    if (m_resultSet.empty()) {
        UpdateARPInfo();
    }
    auto iter = m_resultSet.find(tpa);
    if (iter == m_resultSet.end()) {
        m_header.hrd  = arp->hrd;
        m_header.prot = arp->prot;
        m_header.hln  = arp->hln;
        m_header.pln  = arp->pln;
        m_header.op   = arp->op;
        std::copy(arp->sha, arp->sha + ETH_ALEN, m_header.sha);
        std::copy(arp->spa, arp->spa + IP_LEN, m_header.spa);
        PrintARPHeader();

        if (InsertARPInfoToDB(tpa, tha)) {
            UpdateARPInfo();
            if (m_resultSet.find(tpa) == m_resultSet.end()) {
                LOG_ERROR << "插入失败！";
                return false;
            }
        }
    } else {
        if (iter->second[1].compare("00:00:00:00:00:00") == 0) {
            UpdateARPInfoToDB(tpa, tha);
        }
    }

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
    PrintIP("ARP: target_ip: ", m_header.tpa);
}

bool ARPPacket::InsertARPInfoToDB(std::string ip, std::string mac) {
    std::string sql = "INSERT INTO arp_info (ipv4, mac) VALUES ('";
    sql += ip;
    sql += "', '";
    sql += mac;
    sql += "');";
    return DBManager().ExecuteNonQuery(sql);
}

bool ARPPacket::UpdateARPInfoToDB(std::string ip, std::string mac) {
    std::string sql = "UPDATE arp_info SET mac = '";
    sql += mac;
    sql += "' WHERE ipv4 = '";
    sql += ip;
    sql += "';";
    return DBManager().ExecuteNonQuery(sql);
}

bool ARPPacket::UpdateARPInfo() {
    std::string sql = "select ipv4,mac from arp_info";
    return DBManager().ExecuteQuery(sql, m_resultSet);
}

bool ARPPacket::SendProtocolPacket() {
    std::string targetIP(IPv4ToStr(m_header.tpa));
    auto iter = m_resultSet.find(targetIP);
    if (m_resultSet.empty()) {
        UpdateARPInfo();
    }
    if (iter == m_resultSet.end() || (iter->second[1].compare("00:00:00:00:00:00") == 0)) {
        auto len = sizeof(struct ether_header_t) + sizeof(struct arp_header_t);
        std::unique_ptr<unsigned char[]> packet(new unsigned char[len]());
        if (!packet) {
            LOG_ERROR << "数据包缓冲区内存分配失败";
            return false;
        }

        unsigned char broadcastMac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        ether_header_t etherHeader;
        memcpy(etherHeader.etherDHost , broadcastMac, ETHER_ADDR_LEN);
        memcpy(etherHeader.etherSHost , g_localMachine.m_mac.get(), ETHER_ADDR_LEN);
        etherHeader.etherType = htons(ETHERTYPE_ARP);

        CreateProtocolHeader();

        memcpy(packet.get(), &etherHeader, sizeof(ether_header_t));
        memcpy(packet.get() + sizeof(ether_header_t),
            &m_header, sizeof(arp_header_t));

        int sent = pcap_sendpacket(g_localMachine.m_handler, packet.get(), len);
        if (sent < 0) {
            LOG_ERROR << "pcap_sendpacket failed: "
                        << pcap_geterr(g_localMachine.m_handler);
        } else {
            LOG_INFO << "[success] sent ARP request package..";
        }
    }

    return true;
}

bool ARPPacket::CreateProtocolHeader() {
    m_header.hrd = htons(0x0001);
    m_header.prot = htons(IPV4_PROTOCOL);
    m_header.hln = 6;
    m_header.pln = 4;
    m_header.op = htons(ARPOP_REQUEST);
    memcpy(m_header.sha, g_localMachine.m_mac.get(), ETHER_ADDR_LEN);
    memcpy(m_header.spa, &g_localMachine.m_ip, sizeof(uint32_t));
    bzero(m_header.tha, ETHER_ADDR_LEN);
    return true;
}
