//
// Created by asujy on 2026/1/16.
//

#include "db/MySQLManager.h"
#include "log/Logger.h"
#include "db/ConnectionGuard.h"
#include <iostream>

bool MySQLManager::Init() {
    try {
        m_config = GetConfig();
        MySQLConnectionPool::GetInstance().InitConnectionPool(m_config, 10);

        const std::string createTableSQL = ReadSQLFromFile("sql/arp_info.sql");
        if (createTableSQL.empty()) {
            LOG_ERROR << "读取创建表SQL文件失败";
            return false;
        }
        std::vector<std::string> stmts = SplitSqlStatements(createTableSQL);
        for (const auto &stmt : stmts) {
            if (!ExecuteNonQuery(stmt)) {
                LOG_ERROR << "SQL语句执行失败: " << stmt;
                return false;
            }
        }
        LOG_INFO << "MySQLManager 初始化完成";
        return true;
    } catch (const std::exception &e) {
        LOG_ERROR << "MySQLManager 初始化异常：" << e.what();
        std::cout << "MySQLManager 初始化异常：" << e.what();
        return false;
    }
}

bool MySQLManager::ExecuteNonQuery(const std::string sql) {
    ConnectionGuard guard;
    MYSQL *conn = MySQLConnectionPool::GetInstance().GetConnection();
    if (conn == nullptr) {
        LOG_ERROR << "获取数据库连接失败，无法执行SQL";
        return false;
    }
    guard.BindConnection(conn);

    int ret = mysql_query(conn, sql.c_str());
    if (ret != 0) {
        LOG_ERROR << "SQL执行失败！错误信息：" << mysql_error(conn);
        LOG_ERROR << "失败的SQL：" << sql;
        return false;
    }

    LOG_INFO << "SQL执行成功，影响行数：" << mysql_affected_rows(conn);
    return true;
}

bool MySQLManager::ExecuteQuery(const std::string sql, ResultSet &resultSet) {
    resultSet.clear();
    ConnectionGuard guard;
    MYSQL *conn = MySQLConnectionPool::GetInstance().GetConnection();
    if (conn == nullptr) {
        LOG_ERROR << "获取数据库连接失败，无法执行查询!";
        return false;
    }
    guard.BindConnection(conn);
    // 执行查询SQL
    int ret = mysql_query(conn, sql.c_str());
    if (ret != 0) {
        LOG_ERROR << "查询SQL执行失败！错误信息：" << mysql_error(conn);
        LOG_ERROR << "失败的SQL：" << sql;
        return false;
    }

    // 提取结果集
    MYSQL_RES *res = mysql_store_result(conn);
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

DBConfig MySQLManager::GetConfig() {
    DBConfig dbc;
    boost::property_tree::ptree root;
    boost::property_tree::read_ini("config.ini", root);
    dbc.host = root.get<std::string>("mysql.host");
    dbc.port = root.get<int>("mysql.port");
    dbc.user = root.get<std::string>("mysql.user");
    dbc.passwd = root.get<std::string>("mysql.passwd");
    dbc.dbname = root.get<std::string>("mysql.database");
    dbc.charset = root.get<std::string>("mysql.charset");
    return dbc;
}

std::string MySQLManager::ReadSQLFromFile(const std::string filepath) {
    std::ifstream sqlFile(filepath);
    if (!sqlFile.is_open()) {
        LOG_ERROR << "无法打开SQL文件：" << filepath;
        return "";
    }
    std::stringstream iss;
    iss << sqlFile.rdbuf();
    sqlFile.close();
    return iss.str();
}

std::vector<std::string> MySQLManager::SplitSqlStatements(
    const std::string &sql) {
    std::vector<std::string> statements;
    if (sql.empty()) {
        return statements;
    }

    std::istringstream ss(sql);
    std::string line;
    std::string current_stmt;

    // 状态标记：处理字符串常量、注释，避免误分割字符串内的分号
    bool in_single_quote = false; // 单引号 '
    bool in_double_quote = false; // 双引号 "
    bool in_line_comment = false; // 行内注释 --

    while (std::getline(ss, line)) {
        // 重置行级注释标记
        in_line_comment = false;
        size_t len = line.size();

        for (size_t i = 0; i < len; ++i) {
            char c = line[i];

            // 处理转义字符（MySQL中反斜杠转义）
            if (c == '\\' && (in_single_quote || in_double_quote)) {
                current_stmt += c;
                // 跳过下一个字符，避免误判引号/分号
                if (i + 1 < len) {
                    current_stmt += line[++i];
                }
                continue;
            }

            // 处理引号状态
            if (c == '\'' && !in_double_quote && !in_line_comment) {
                in_single_quote = !in_single_quote;
                current_stmt += c;
                continue;
            }
            if (c == '"' && !in_single_quote && !in_line_comment) {
                in_double_quote = !in_double_quote;
                current_stmt += c;
                continue;
            }

            // 处理行注释 -- ，注释后内容全部忽略
            if (!in_single_quote && !in_double_quote && i + 1 < len
                && c == '-' && line[i + 1] == '-') {
                in_line_comment = true;
                current_stmt += c;
                current_stmt += line[++i];
                continue;
            }

            // 注释状态下，直接拼接字符，不处理分号
            if (in_line_comment) {
                current_stmt += c;
                continue;
            }

            // 核心逻辑：非字符串/注释状态下，遇到分号表示语句结束
            if (c == ';' && !in_single_quote && !in_double_quote && !
                in_line_comment) {
                current_stmt += c;
                // 去除语句首尾空白字符
                size_t start = current_stmt.find_first_not_of(" \t\n\r");
                if (start != std::string::npos) {
                    size_t end = current_stmt.find_last_not_of(" \t\n\r");
                    std::string valid_stmt = current_stmt.substr(
                        start, end - start + 1);
                    // 过滤纯空白/纯注释的无效语句
                    if (!valid_stmt.empty()) {
                        statements.push_back(valid_stmt);
                    }
                }

                // 重置缓冲区，准备接收下一条语句
                current_stmt.clear();
                continue;
            }

            // 普通字符，直接拼接
            current_stmt += c;
        }
    }

    // 处理文件末尾未以分号结尾的剩余语句（兼容异常格式）
    if (!current_stmt.empty()) {
        size_t start = current_stmt.find_first_not_of(" \t\n\r");
        if (start != std::string::npos) {
            size_t end = current_stmt.find_last_not_of(" \t\n\r");
            std::string valid_stmt = current_stmt.
                substr(start, end - start + 1);
            if (!valid_stmt.empty()) {
                statements.push_back(valid_stmt);
            }
        }
    }

    return statements;
}