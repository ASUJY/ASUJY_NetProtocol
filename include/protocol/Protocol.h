//
// Created by asujy on 2026/1/15.
//

#ifndef PROTOCOL_H
#define PROTOCOL_H

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
    T1 GetHeader();
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


#endif //PROTOCOL_H
