//
// Created by asujy on 2026/1/15.
//

#ifndef PROTOCOL_H
#define PROTOCOL_H

#define IPV4_PROTOCOL   0x0800

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
    bool SendProtocolPacket();
    T1 GetHeader();
    void SetTargetIP(uint32_t ip);
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
bool Protocol<T, T1>::SendProtocolPacket() {
    return m_packet.SendProtocolPacket();
}

template <typename T, typename T1>
void Protocol<T, T1>::SetTargetIP(uint32_t ip) {
    m_packet.SetTargetIP(ip);
}

#endif //PROTOCOL_H
