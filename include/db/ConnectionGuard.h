//
// Created by asujy on 2026/2/6.
//

#ifndef CONNECTIONGUARD_H
#define CONNECTIONGUARD_H

#include <mysql/mysql.h>

class ConnectionGuard {
public:
    ConnectionGuard() : m_conn(nullptr) {
    }

    void BindConnection(MYSQL* conn) {
        m_conn = conn;
    }

    ~ConnectionGuard() {
        if (m_conn) {
            MySQLConnectionPool::GetInstance().ReturnConnetion(m_conn);
        }
    }

    MYSQL* get() const {
        return m_conn;
    }

    ConnectionGuard(const ConnectionGuard&) = delete;
    ConnectionGuard& operator=(const ConnectionGuard&) = delete;

    ConnectionGuard(ConnectionGuard&& other) noexcept : m_conn(other.m_conn) {
        other.m_conn = nullptr;
    }

    ConnectionGuard& operator=(ConnectionGuard&& other) noexcept {
        if (this != nullptr) {
            if (m_conn) {
                MySQLConnectionPool::GetInstance().ReturnConnetion(m_conn);
            }
            m_conn = other.m_conn;
        }
        return *this;
    }

private:
    MYSQL* m_conn;
};

#endif //CONNECTIONGUARD_H
