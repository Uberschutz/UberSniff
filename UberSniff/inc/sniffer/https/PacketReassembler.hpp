#pragma once

#include <queue>
#include <regex>
#include <tins/tcp_ip/stream.h>
#include "collector/DataCollector.hpp"
#include "packet/Exchange.hpp"
#include "packet/Response.hpp"
#include "packet/Request.hpp"
#include "packet/HTTPReassembler.hpp"

namespace ubersniff::sniffer::https {
	/*
	* This class reassemble the HTTP packet exchanges captured by the the sniffer
	* Each reassembled exchange will be send to the DataCollector
	*/
	class PacketReassembler {
		packet::HTTPReassembler _http_reassembler;

		void _on_server_data(Tins::TCPIP::Stream& stream);
		void _on_client_data(Tins::TCPIP::Stream& stream);
	public:
		PacketReassembler(Tins::TCPIP::Stream& stream, collector::DataCollector& data_collector);
		~PacketReassembler();
	};
}
