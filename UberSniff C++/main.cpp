#ifndef NOMINMAX
# define NOMINMAX
#endif

#include <atomic>
#include <csignal>
#include <iostream>
#include <stdexcept>
#include <chrono>
#include <thread>
#include <tins/network_interface.h>
#include "api/UberBack.hpp"
#include "collector/DataCollector.hpp"
#include "sniffer/http/Sniffer.hpp"
#include "sniffer/https/Sniffer.hpp"

volatile std::atomic<bool> quit(false); // signal flag

void got_signal(int)
{
    quit.store(true);
}

#ifdef _WIN32
BOOL WINAPI got_ctrl_routine(_In_ DWORD dwCtrlType)
{
    switch (dwCtrlType) {
    case CTRL_C_EVENT:
        quit.store(true);
        return TRUE;
    default:
        return FALSE;
    }
}
#endif // !_WIN32

std::string get_interface_name()
{
    auto iface = Tins::NetworkInterface::default_interface();
    auto interface_name = std::string(iface.name());
    return interface_name;
}

ubersniff::api::UberBack init_uberback()
{
    ubersniff::api::UberBack::Config config;
    config.service = "UberSniff";
    config.host = "127.0.0.1";
    config.port = "5412";
    config.token = "tokendesesmorts";
    config.userId = "testUser";

    return ubersniff::api::UberBack(config);
}

int main(int argc, char* argv[])
{
    try {
        std::signal(SIGTERM, got_signal);
#ifdef _WIN32
        SetConsoleCtrlHandler(got_ctrl_routine, TRUE);
#else
        std::signal(SIGINT, got_signal);
#endif // !_WIN32

        auto interface_name = get_interface_name();
        auto uberback = init_uberback();
        auto data_collector = ubersniff::collector::DataCollector();
        auto http_sniffer = ubersniff::sniffer::http::Sniffer(interface_name, data_collector);
        auto https_sniffer = ubersniff::sniffer::https::Sniffer(interface_name, data_collector);
        std::cout << "Starting capture on interface " << interface_name << std::endl;

        http_sniffer.start_sniffing();
        https_sniffer.start_sniffing();
        auto is_dumped = false;

        while (!quit.load()) {
            // check default interface
            auto new_interface_name = get_interface_name();
            if (interface_name != new_interface_name) {
                interface_name = new_interface_name;
                std::cout << "Change capture on interface " << interface_name << std::endl;
                http_sniffer.change_interface(interface_name);
                https_sniffer.change_interface(interface_name);
            }
            if (!data_collector.process_next_exchanges()) {
                if (!is_dumped) {
                    data_collector.dump();
                    is_dumped = true;
                    // analyse the collected data
                    uberback.analyze_data(std::move(data_collector.extract_data_batches()));
                }
                auto sleeping_time = std::chrono::milliseconds(100);
                std::this_thread::sleep_for(sleeping_time);
            } else {
                is_dumped = false;
            }
        }
 
        std::cout << "quit" << std::endl;
        http_sniffer.stop_sniffing();
    }
    catch (std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }
}
