//
// Created by asujy on 2026/1/15.
//

#ifndef PROTOCOL_H
#define PROTOCOL_H

template<typename T>
class Protocol {
public:
    Protocol() = default;
    Protocol(const Protocol&) = default;
    Protocol& operator=(const Protocol&) = default;
    Protocol(Protocol&&) = default;
    Protocol& operator=(Protocol&&) = default;
    ~Protocol() = default;

    bool ParseProtocolHeader(const unsigned char* packet);
};

template <typename T>
bool Protocol<T>::ParseProtocolHeader(const unsigned char* packet) {
    T prot;
    return prot.ParseProtocolHeader(packet);
}


#endif //PROTOCOL_H
