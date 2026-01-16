cmake_minimum_required(VERSION 3.16)
project(NetProtocol)

set(CMAKE_CXX_STANDARD 11)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

link_libraries(/usr/lib/x86_64-linux-gnu/libpcap.so.0.8)

add_executable(${PROJECT_NAME}
    main.cpp
    src/Utils.cpp
)

target_link_libraries(
    ${PROJECT_NAME}
    log
    handler
    protocol
)

add_subdirectory(src/log)
add_subdirectory(src/handler)
add_subdirectory(src/protocol)