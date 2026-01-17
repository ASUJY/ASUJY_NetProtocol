//
// Created by asujy on 2026/1/16.
//

#ifndef ARPPACKET_H
#define ARPPACKET_H

#include <cstring>
#include <netinet/ether.h>
#include "db/MySQLManager.h"

constexpr int IP_LEN = 4;

struct arp_header_t {
    unsigned short int hrd{0};        // 硬件类型(hardware address type)
    unsigned short int prot{0};       // 协议类型(protocol type)
    unsigned char hln{};              // 硬件地址大小，单位字节(Length of hardware address)
    unsigned char pln{};              // 协议地址大小，单位字节(Length of protocol address)
    unsigned short int op{0};         // arp协议操作码(ARP opcode (command))
    uint8_t sha[ETH_ALEN]{0};         // 发送方的硬件地址(sender hardware address)
    uint8_t spa[IP_LEN]{0};           // 发送方的ip地址(sender protocol address)
    uint8_t tha[ETH_ALEN]{0};         // 目的硬件地址(target hardware address)
    uint8_t tpa[IP_LEN]{0};           // 目的ip地址(target protocol address)
} __attribute__ ((__packed__));

class ARPPacket {
    using ResultSet = std::map<std::string, std::vector<std::string>>;
public:
    ARPPacket() = default;
    ARPPacket(const ARPPacket&) = default;
    ARPPacket& operator=(const ARPPacket&) = default;
    ARPPacket(ARPPacket&&) = default;
    ARPPacket& operator=(ARPPacket&&) = default;
    ~ARPPacket() = default;

    bool ParseProtocolHeader(const unsigned char* packet);
    bool SendProtocolPacket();
    bool CreateProtocolHeader();
    arp_header_t GetHeader() const{
        return m_header;
    }
    void SetTargetIP(uint32_t ip) {
        memcpy(m_header.tpa, &ip, sizeof(uint32_t));
    }

private:
    void PrintARPHeader();

    static MySQLManager& DBManager() {
        static MySQLManager dbManager;
        return dbManager;
    }
    bool InsertARPInfoToDB(std::string ip, std::string mac);
    bool UpdateARPInfoToDB(std::string ip, std::string mac);
    bool UpdateARPInfo();
private:
    arp_header_t m_header;
    static ResultSet m_resultSet;
};

#endif //ARPPACKET_H
