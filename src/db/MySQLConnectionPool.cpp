//
// Created by asujy on 2026/2/6.
//

#include <mysql/mysql.h>
#include <thread>

#include "db/MySQLConnectionPool.h"
#include "log/Logger.h"

void MySQLConnectionPool::InitConnectionPool(const struct DBConfig &config,
                                             int maxConnections) {
    std::lock_guard<std::mutex> locker(m_mtx);
    if (m_inited) {
        LOG_INFO << "连接池已初始化，无需重复执行";
        return;
    }
    m_config = config;
    m_maxConnections = maxConnections;

    for (int i = 0; i < m_maxConnections; ++i) {
        MYSQL *conn = CreateConnection();
        if (conn) {
            m_idleConnections.push(conn);
        } else {
            LOG_ERROR << "创建第" << i + 1 << "个数据库连接失败";
        }
    }
    m_inited = true;
    LOG_INFO << "MySQL连接池初始化完成，总连接数：" << m_idleConnections.size();
}

MYSQL *MySQLConnectionPool::GetConnection() {
    std::unique_lock<std::mutex> locker(m_mtx);
    while (m_idleConnections.empty() && m_inited) {
        m_cv.wait(locker);
        if (!m_inited) {
            LOG_ERROR << "连接池已销毁，无法获取连接";
            return nullptr;
        }
    }

    if (!m_inited) {
        return nullptr;
    }

    // 取出连接并检测可用性
    MYSQL *conn = m_idleConnections.front();
    m_idleConnections.pop();
    if (mysql_ping(conn) != 0) {
        LOG_WARN << "检测到无效连接，重新创建...";
        mysql_close(conn);
        conn = nullptr;

        const int retryTimes = 3;
        for (int i = 0; i < retryTimes && !conn; ++i) {
            conn = CreateConnection();
            if (!conn) {
                LOG_WARN << "第" << i + 1 << "次创建连接失败，尝试重试...";
                // 短暂休眠，避免密集重试
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
        }
        if (conn) {
            m_idleConnections.push(conn);
            LOG_INFO << "重建连接成功，已补充至连接池空闲队列";
            // 重新从队列获取刚补充的连接，保证逻辑统一
            conn = m_idleConnections.front();
            m_idleConnections.pop();
        } else {
            LOG_ERROR << "重试" << retryTimes << "次后，仍无法创建有效连接";
            // 连接创建彻底失败，通知其他线程，返回空指针
            m_cv.notify_one();
            return nullptr;
        }
    }
    m_cv.notify_one();
    return conn;
}

void MySQLConnectionPool::ReturnConnetion(MYSQL *conn) {
    if (!conn || !m_inited) {
        return;
    }

    std::lock_guard<std::mutex> locker(m_mtx);
    m_idleConnections.push(conn);
    m_cv.notify_one();
}

void MySQLConnectionPool::DestroyPool() {
    std::lock_guard<std::mutex> locker(m_mtx);
    m_inited = false;
    m_cv.notify_all(); // 唤醒所有等待线程

    // 关闭所有空闲连接
    while (!m_idleConnections.empty()) {
        MYSQL *conn = m_idleConnections.front();
        m_idleConnections.pop();
        mysql_close(conn);
    }
    LOG_INFO << "MySQL连接池已销毁，所有连接已释放";
}

MYSQL *MySQLConnectionPool::CreateConnection() {
    MYSQL *conn = mysql_init(nullptr);
    if (conn == nullptr) {
        LOG_ERROR << "Init Mysql Handler Failed!!!";
        return nullptr;
    }

    MYSQL *ret = mysql_real_connect(conn,
                                    m_config.host.c_str(),
                                    m_config.user.c_str(),
                                    m_config.passwd.c_str(),
                                    m_config.dbname.c_str(),
                                    m_config.port,
                                    nullptr,
                                    0);
    if (ret == nullptr) {
        LOG_ERROR << "数据库连接失败！错误信息：" << mysql_error(conn);
        mysql_close(conn);
        return nullptr;
    }
    // 设置数据库编码
    if (mysql_set_character_set(conn, m_config.charset.c_str()) != 0) {
        LOG_WARN << "设置字符集失败，可能导致中文乱码。" << mysql_error(conn);
    }
    return conn;
}