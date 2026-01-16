//
// Created by asujy on 2026/1/16.
//

#ifndef MYSQLMANAGER_H
#define MYSQLMANAGER_H

#include <map>
#include <vector>
#include <mysql/mysql.h>

class MySQLManager {
    using ResultSet = std::map<std::string, std::vector<std::string>>;
public:
    MySQLManager(const std::string host = "localhost",
        const std::string user = "root", const std::string passwd = "root",
        const std::string dbname = "netdb", std::uint16_t port = DEFAULT_PORT,
        const std::string charset = DEFAULT_CHARSET);
    ~MySQLManager();

    MySQLManager(const MySQLManager&) = delete;
    MySQLManager& operator=(const MySQLManager&) = delete;
    MySQLManager(MySQLManager&&) = delete;
    MySQLManager& operator=(MySQLManager&&) = delete;

    // 执行非查询SQL（CREATE/INSERT/UPDATE/DELETE）
    bool ExecuteNonQuery(const std::string sql);
    // 执行查询SQL
    bool ExecuteQuery(const std::string sql, ResultSet& resultSet);

private:
    bool Connect(const std::string host, const std::string user,
                    const std::string passwd, std::string dbName,
                    std::uint16_t port = DEFAULT_PORT,
                    const std::string charset = DEFAULT_CHARSET);
private:
    MYSQL* m_conn{nullptr};
    static constexpr std::uint16_t DEFAULT_PORT = 3306;
    static constexpr const char* DEFAULT_CHARSET = "utf8mb4";
};

#endif //MYSQLMANAGER_H
