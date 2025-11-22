cmake_minimum_required(VERSION 3.10)
project(packet_sniffer)

set(CMAKE_CXX_STANDARD 17)

find_package(Pcap REQUIRED) # If your CMake doesn't find pcap, define include/link manually.

add_executable(packet_sniffer main.cpp)
target_include_directories(packet_sniffer PRIVATE ${PCAP_INCLUDE_DIR})
target_link_libraries(packet_sniffer PRIVATE ${PCAP_LIBRARY})
