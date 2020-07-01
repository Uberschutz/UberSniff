#include <iostream>
#include <algorithm>
#include <tins/tins.h>

int main(int ac, char** av)
{
    Tins::EthernetII eth;
    Tins::IP* ip = new Tins::IP();
    Tins::TCP* tcp = new Tins::TCP();

    // tcp is ip's inner pdu
    ip->inner_pdu(tcp);

    // ip is eth's inner pdu
    eth.inner_pdu(ip);
	return EXIT_SUCCESS;
}
