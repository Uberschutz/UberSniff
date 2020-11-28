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
#include "config/Config.hpp"
#include "sniffer/http/Sniffer.hpp"

/* Bollean flag that will quit the program when set at true */
volatile std::atomic<bool> quit(false);

/* Set the quit flag at true. should be called when the signal handling */
void got_signal(int)
{
    quit.store(true);
}

#ifdef _WIN32
/* Catch Ctrl+C for windows */
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

/* get the default interface */
std::string get_interface_name()
{
    auto iface = Tins::NetworkInterface::default_interface();
    auto interface_name = std::string(iface.name());
    return interface_name;
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cerr << "Invalid number of argument: " << argv[0] << " <config_file.xml>" << std::endl;
        return EXIT_FAILURE;
    }

    try {
        std::signal(SIGTERM, got_signal);
#ifdef _WIN32
        SetConsoleCtrlHandler(got_ctrl_routine, TRUE);
#else
        std::signal(SIGINT, got_signal);
#endif // !_WIN32

        auto config = ubersniff::config::Config(argv[1]);
        auto interface_name = get_interface_name();
        auto uberback = ubersniff::api::UberBack(config.get_uberback_config());
        auto data_collector = ubersniff::collector::DataCollector();
        auto http_sniffer = ubersniff::sniffer::http::Sniffer(interface_name, data_collector);
        std::cout << "Starting capture on interface " << interface_name << std::endl;

        http_sniffer.start_sniffing();
        auto is_analysed = false;

        while (!quit.load()) {
            // check default interface
            auto new_interface_name = get_interface_name();
            if (interface_name != new_interface_name) {
                interface_name = new_interface_name;
                std::cout << "Change capture on interface " << interface_name << std::endl;
                http_sniffer.change_interface(interface_name);
            }
            if (!data_collector.process_next_exchanges()) {
                if (!is_analysed) {
                    //data_collector.dump();
                    is_analysed = true;
                    // analyse the collected data
                    uberback.analyze_data(std::move(data_collector.extract_data_batches()));
                }
                auto sleeping_time = std::chrono::milliseconds(100);
                std::this_thread::sleep_for(sleeping_time);
            } else {
                is_analysed = false;
            }
        }
 
        std::cout << "quit" << std::endl;
        http_sniffer.stop_sniffing();
    }
    catch (std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
