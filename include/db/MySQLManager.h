//
// Created by asujy on 2026/1/16.
//

#ifndef MYSQLMANAGER_H
#define MYSQLMANAGER_H

#include <map>
#include <vector>
#include <fstream>
#include <boost/property_tree/ini_parser.hpp>
#include "MySQLConnectionPool.h"

class MySQLManager {
    using ResultSet = std::map<std::string, std::vector<std::string>>;

public:
    ~MySQLManager() = default;

    MySQLManager(const MySQLManager&) = delete;
    MySQLManager& operator=(const MySQLManager&) = delete;
    MySQLManager(MySQLManager&&) = delete;
    MySQLManager& operator=(MySQLManager&&) = delete;

    static MySQLManager& GetInstance() {
        static MySQLManager instance;
        return instance;
    }

    bool Init();

    void Destroy() {
        MySQLConnectionPool::GetInstance().DestroyPool();
    }

    // 执行非查询SQL（CREATE/INSERT/UPDATE/DELETE）
    bool ExecuteNonQuery(const std::string sql);
    // 执行查询SQL
    bool ExecuteQuery(const std::string sql, ResultSet& resultSet);

private:
    MySQLManager() = default;
    DBConfig GetConfig();
    std::string ReadSQLFromFile(const std::string filepath);
    std::vector<std::string> SplitSqlStatements(const std::string& sql);

private:
    DBConfig m_config;
};

#endif //MYSQLMANAGER_H
