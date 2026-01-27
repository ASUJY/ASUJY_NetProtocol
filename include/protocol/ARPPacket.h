//
// Created by asujy on 2026/1/16.
//

#ifndef ARPPACKET_H
#define ARPPACKET_H

#include <mutex>
#include <netinet/ether.h>
#include "db/MySQLManager.h"
#include "protocol/Protocol.h"

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
    bool SendProtocolPacket(const Machine_t &localMachine,
        const Machine_t &targetMachine);
    bool CreateProtocolHeader(const Machine_t &localMachine,
        const Machine_t &targetMachine);
    arp_header_t GetHeader() const{
        return m_header;
    }

    static bool IsContainsKey(const std::string& key) {
        std::lock_guard<std::mutex> lock(m_mtx);
        return m_resultSet.find(key) != m_resultSet.end();
    }
    static bool GetResultSetElement(
        const std::string& key, std::vector<std::string>& outValue) {
        std::lock_guard<std::mutex> locker(m_mtx);
        auto iter = m_resultSet.find(key);
        if (iter != m_resultSet.end()) {
            outValue = iter->second;
            return true;
        }
        return false;
    }
    static bool IsResultSetEmpty() {
        std::lock_guard<std::mutex> lock(ARPPacket::m_mtx);
        return m_resultSet.empty();
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
    static std::mutex m_mtx;
};

#endif //ARPPACKET_H
