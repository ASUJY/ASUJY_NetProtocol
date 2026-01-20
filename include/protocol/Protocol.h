//
// Created by asujy on 2026/1/15.
//

#ifndef PROTOCOL_H
#define PROTOCOL_H

#define IPV4_PROTOCOL   0x0800
#define IP_PROTOCOL_ICMP    1

#include "machine.h"

template<typename T, typename T1>
class Protocol {
public:
    Protocol() = default;
    Protocol(const Protocol&) = default;
    Protocol& operator=(const Protocol&) = default;
    Protocol(Protocol&&) = default;
    Protocol& operator=(Protocol&&) = default;
    ~Protocol() = default;

    bool ParseProtocolHeader(const unsigned char* packet);
    bool SendProtocolPacket(const Machine_t &localMachine,
        const Machine_t &targetMachine);
    T1 GetHeader();
    void SetFlag(uint8_t flag);
    void SetSeqNum(uint32_t num);
    void SetAckNum(uint32_t num);
private:
    T m_packet;
};

template <typename T, typename T1>
bool Protocol<T, T1>::ParseProtocolHeader(const unsigned char* packet) {
    return m_packet.ParseProtocolHeader(packet);
}

template <typename T, typename T1>
T1 Protocol<T, T1>::GetHeader() {
    return m_packet.GetHeader();
}

template <typename T, typename T1>
bool Protocol<T, T1>::SendProtocolPacket(const Machine_t &localMachine,
    const Machine_t &targetMachine) {
    return m_packet.SendProtocolPacket(localMachine, targetMachine);
}

template <typename T, typename T1>
void Protocol<T, T1>::SetFlag(uint8_t flag) {
    m_packet.SetFlag(flag);
}

template <typename T, typename T1>
void Protocol<T, T1>::SetAckNum(uint32_t num) {
    m_packet.SetAckNum(num);
}

template <typename T, typename T1>
void Protocol<T, T1>::SetSeqNum(uint32_t num) {
    m_packet.SetSeqNum(num);
}

#endif //PROTOCOL_H
