#include <iostream>
#include <stdexcept>
#include "tins/network_interface.h"
#include "sniffer/http/Sniffer.hpp"

int main(int argc, char* argv[])
{
    try {
        std::string interface_name;
        if (argc != 2) {
            Tins::NetworkInterface iface = Tins::NetworkInterface::default_interface();
            interface_name = std::string(iface.name());
            std::cout << "Starting capture on interface " << interface_name;
            std::wcout << " (" << iface.friendly_name() << ")" << std::endl;
        } else {
            interface_name = std::string(argv[1]);
            std::cout << "Starting capture on interface " << interface_name << std::endl;
        }

        auto http_sniffer = ubersniff::sniffer::http::Sniffer(interface_name);
        http_sniffer.start_sniffing();

        std::cout << "Press enter to exit" << std::endl;
        std::cin.ignore();
        http_sniffer.stop_sniffing();
    }
    catch (std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }
}
