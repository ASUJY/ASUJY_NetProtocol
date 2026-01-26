//
// Created by asujy on 2026/1/26.
//

#ifndef CMDUTILS_H
#define CMDUTILS_H

#include <getopt.h>
#include <string>

struct Option {
    int exec = -1;
    std::string targetIp;
    std::string targetPort;
    std::string localPort;
    std::string protocol;
};

void CmdHandler(int argc, char* argv[], Option &option);

#endif //CMDUTILS_H
