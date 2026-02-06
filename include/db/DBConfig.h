//
// Created by asujy on 2026/2/6.
//

#ifndef DBCONFIG_H
#define DBCONFIG_H

struct DBConfig {
    std::string host;
    std::string user;
    std::string passwd;
    std::string dbname;
    std::uint16_t port;
    std::string charset;
};

#endif //DBCONFIG_H
