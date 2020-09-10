#pragma once

#include <thread>
#include <map>
#include <tins/tcp_ip/stream_follower.h>
#include <tins/sniffer.h>
#include "sniffer/ISniffer.hpp"
#include "sniffer/http/PacketReassembler.hpp"
#include "collector/DataCollector.hpp"

namespace ubersniff::sniffer::http {
	/*
	* HTTP Sniffer
	*/
	class Sniffer : public ISniffer {
		static constexpr size_t TIMEOUT = 100;

		collector::DataCollector &_data_collector;

		// Sniffer
		Tins::SnifferConfiguration _sniffer_config;
		Tins::Sniffer _sniffer;
		Tins::TCPIP::StreamFollower _stream_follower;
		std::map<Tins::TCPIP::StreamIdentifier, std::unique_ptr<PacketReassembler>> _packet_reassemblers;

		std::thread _sniffer_thread;
		bool _is_sniffing = false;

		// sniffer callbacks
		void _on_new_connection(Tins::TCPIP::Stream& stream);
	public:
		Sniffer(const std::string &interface_name, collector::DataCollector &data_collector);
		virtual ~Sniffer();
	
		bool is_sniffing() { return _is_sniffing; }

		// start the sniffing of the packets in a different thread
		void start_sniffing();
		// stop the sniffing of the packets
		void stop_sniffing();

		void change_interface(const std::string &interface_name);
	};
}
