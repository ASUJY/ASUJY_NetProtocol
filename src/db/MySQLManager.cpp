//
// Created by asujy on 2026/1/16.
//

#include "db/MySQLManager.h"
#include "log/Logger.h"

MySQLManager::MySQLManager(const std::string host, const std::string user,
        const std::string passwd, const std::string dbname,
        std::uint16_t port, const std::string charset) {
    m_conn = mysql_init(nullptr);
    if (m_conn == nullptr) {
        LOG_ERROR << "Init Mysql Handler Failed!!!";
        std::exit(EXIT_FAILURE);
    }

    bool isConnected =
        Connect(host, user, passwd, dbname, port, charset);
    if (!isConnected) {
        LOG_ERROR << "Connect DB Failed!!";
        std::exit(EXIT_FAILURE);
    }

    const std::string createTableSQL = R"(
            CREATE TABLE IF NOT EXISTS arp_info (
                id INT PRIMARY KEY AUTO_INCREMENT,
                ipv4 CHAR(15) NOT NULL COMMENT 'IPv4地址(点分十进制)',
                mac CHAR(17) NOT NULL COMMENT 'MAC地址',
                create_time DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间'
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='arp信息表';
        )";
    ExecuteNonQuery(createTableSQL);
}

MySQLManager::~MySQLManager() {
    if (m_conn != nullptr) {
        mysql_close(m_conn);
        m_conn = nullptr;
        LOG_INFO << "MySQL连接已断开，资源已释放!";
    }
}

bool MySQLManager::Connect(const std::string host, const std::string user,
    const std::string passwd, std::string dbName,
    std::uint16_t port, const std::string charset) {
    if (m_conn == nullptr) {
        LOG_ERROR << "MySQL句柄未初始化，无法建立连接。";
        return false;
    }

    MYSQL* retConn =
        mysql_real_connect(m_conn, host.c_str(), user.c_str(),
            passwd.c_str(), dbName.c_str(), port, nullptr, 0);
    if (retConn == nullptr) {
        LOG_ERROR << "数据库连接失败！错误信息：" << mysql_error(m_conn);
        return false;
    }

    // 设置数据库编码
    if (mysql_set_character_set(m_conn, charset.c_str()) != 0) {
        LOG_WARN << "设置字符集失败，可能导致中文乱码。";
    }

    LOG_INFO << "数据库连接成功！";
    return true;
}

bool MySQLManager::ExecuteNonQuery(const std::string sql) {
    if (m_conn == nullptr) {
        LOG_ERROR << "MySQL句柄未初始化，无法执行SQL";
        return false;
    }

    int ret = mysql_query(m_conn, sql.c_str());
    if (ret != 0) {
        LOG_ERROR << "SQL执行失败！错误信息：" << mysql_error(m_conn);
        LOG_ERROR << "失败的SQL：" << sql;
        return false;
    }

    LOG_INFO << "SQL执行成功，影响行数：" << mysql_affected_rows(m_conn);
    return true;
}

bool MySQLManager::ExecuteQuery(const std::string sql, ResultSet& resultSet) {
    resultSet.clear();
    if (m_conn == nullptr) {
        LOG_ERROR << "MySQL句柄未初始化，无法执行查询!";
        return false;
    }

    // 执行查询SQL
    int ret = mysql_query(m_conn, sql.c_str());
    if (ret != 0) {
        LOG_ERROR << "查询SQL执行失败！错误信息：" << mysql_error(m_conn);
        LOG_ERROR << "失败的SQL：" << sql;
        return false;
    }

    // 提取结果集
    MYSQL_RES* res = mysql_store_result(m_conn);
    if (res == nullptr) {
        LOG_ERROR << "提取结果集失败!";
        return false;
    }
    unsigned int fieldCount = mysql_num_fields(res);
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res)) != nullptr) {
        std::vector<std::string> second;
        std::string first = row[0] ? std::string(row[0]) : "NULL";
        for (unsigned int i = 0; i < fieldCount; ++i) {
            second.push_back(row[i] ? std::string(row[i]) : "NULL");
        }
        resultSet[first] = second;
    }
    mysql_free_result(res);

    LOG_INFO << "查询成功，返回 " << resultSet.size() << " 条记录。";
    return true;
}