//
// Created by asujy on 2026/2/6.
//

#ifndef MYSQLCONNECTIONPOOL_H
#define MYSQLCONNECTIONPOOL_H

#include <queue>
#include <condition_variable>
#include <mysql/mysql.h>
#include "DBConfig.h"

class MySQLConnectionPool {
public:
    MySQLConnectionPool(const MySQLConnectionPool&) = delete;
    MySQLConnectionPool& operator=(const MySQLConnectionPool&) = delete;
    MySQLConnectionPool(MySQLConnectionPool&&) = delete;
    MySQLConnectionPool& operator=(MySQLConnectionPool&&) = delete;

    // 单例模式
    static MySQLConnectionPool& GetInstance() {
        static MySQLConnectionPool pool;
        return pool;
    }

    // 初始化数据库连接池
    void InitConnectionPool(const struct DBConfig& config, int maxConnections = 10);

    // 获取空闲连接
    MYSQL* GetConnection();
    void ReturnConnetion(MYSQL* conn);
    void DestroyPool();

private:
    MySQLConnectionPool() : m_inited(false), m_maxConnections(0) {
    };
    MYSQL* CreateConnection();

private:
    bool m_inited;
    int m_maxConnections;
    DBConfig m_config;
    std::queue<MYSQL*> m_idleConnections;
    std::mutex m_mtx;
    std::condition_variable m_cv;
};

#endif //MYSQLCONNECTIONPOOL_H
