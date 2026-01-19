//
// Created by asujy on 2026/1/17.
//

#ifndef THREADUTILS_H
#define THREADUTILS_H

#include "machine.h"

void Worker(Machine_t &localMachine, Machine_t &targetMachine,
    std::string protocolType);

#endif //THREADUTILS_H
