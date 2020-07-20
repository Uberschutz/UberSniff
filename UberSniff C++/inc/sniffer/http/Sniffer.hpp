#pragma once

#include <thread>
#include <map>
#include <tins/tcp_ip/stream_follower.h>
#include <tins/sniffer.h>
#include "sniffer/ISniffer.hpp"
#include "sniffer/http/PacketReassembler.hpp"

namespace ubersniff::sniffer::http {
	class Sniffer : public ISniffer {
		static constexpr size_t TIMEOUT = 100;

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
		Sniffer(const std::string &interface_name);
		virtual ~Sniffer();
	
		void start_sniffing();
		void stop_sniffing();

		bool is_sniffing() { return _is_sniffing; }
	};
}
