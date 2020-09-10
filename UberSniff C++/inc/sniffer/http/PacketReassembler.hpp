#pragma once

#include <queue>
#include <regex>
#include <tins/tcp_ip/stream.h>
#include "collector/DataCollector.hpp"
#include "packet/Exchange.hpp"
#include "packet/Response.hpp"
#include "packet/Request.hpp"

namespace ubersniff::sniffer::http {
	using Exchanges = ubersniff::packet::Exchange;
	using Response = ubersniff::packet::Response;
	using Request = ubersniff::packet::Request;
	using ContentType = ubersniff::packet::ContentType;

	/*
	* This class reassemble the HTTP packet exchanges captured by the the sniffer
	* Each reassembled exchange will be send to the DataCollector
	*/
	class PacketReassembler {
		collector::DataCollector& _data_collector;

		std::vector<uint8_t> _request_data_buffer;
		std::vector<uint8_t> _response_data_buffer;

		std::queue<Request> _request_packets;

		bool _is_reassembling_a_request_packet = false;
		Request _reassembling_request_packet;

		bool _is_reassembling_a_server_response_headers = false;
		bool _is_reassembling_a_response_packet_content = false;
		size_t _response_packet_content_size = 0;
		Response _reassembling_response_packet;

		void _on_server_data(Tins::TCPIP::Stream& stream);
		void _on_client_data(Tins::TCPIP::Stream& stream);

		std::list<std::vector<uint8_t>> _extract_headers(std::vector<uint8_t>& data_buffer);
		void _reassemble_request_packets(std::list<std::vector<uint8_t>>&& request_headers);
		void _reassemble_reponse_packets(std::list<std::vector<uint8_t>>&& response_headers);
		void _reassemble_reponse_packets_content(std::vector<uint8_t>& data);
		void _reassemble_reponse_packets_header(const std::vector<uint8_t>& data);

		void _process_http_packets(Exchanges exchanges);
	public:
		PacketReassembler(Tins::TCPIP::Stream& stream, collector::DataCollector& data_collector);
		~PacketReassembler();
	};
}
