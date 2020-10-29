#include <iostream>
#include "sniffer/http/PacketReassembler.hpp"

namespace ubersniff::sniffer::http {
	PacketReassembler::PacketReassembler(Tins::TCPIP::Stream& stream, collector::DataCollector& data_collector):
		_http_reassembler(data_collector, "http://")
	{
		stream.client_data_callback(std::bind(&PacketReassembler::_on_client_data, this, std::placeholders::_1));
		stream.server_data_callback(std::bind(&PacketReassembler::_on_server_data, this, std::placeholders::_1));
	}

	PacketReassembler::~PacketReassembler()
	{}

	void PacketReassembler::_on_client_data(Tins::TCPIP::Stream& stream)
	{
		_http_reassembler.push_client_payload(stream.client_payload());
	}

	void PacketReassembler::_on_server_data(Tins::TCPIP::Stream& stream)
	{
		_http_reassembler.push_server_payload(stream.server_payload());
	}
}
