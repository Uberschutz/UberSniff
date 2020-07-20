#pragma once

#include <queue>
#include <regex>
#include <tins/tcp_ip/stream.h>
#include "sniffer/http/ResponsePacket.hpp"
#include "sniffer/http/RequestPacket.hpp"

namespace ubersniff::sniffer::http {
	class PacketReassembler {
		std::vector<uint8_t> _request_data_buffer;
		std::vector<uint8_t> _response_data_buffer;

		std::queue<RequestPacket> _request_packets;

		bool _is_reassembling_a_request_packet = false;
		RequestPacket _reassembling_request_packet;

		bool _is_reassembling_a_server_response_headers = false;
		bool _is_reassembling_a_response_packet_content = false;
		size_t _response_packet_content_size = 0;
		ResponsePacket _reassembling_response_packet;

		void _on_server_data(Tins::TCPIP::Stream& stream);
		void _on_client_data(Tins::TCPIP::Stream& stream);

		std::list<std::vector<uint8_t>> _extract_headers(std::vector<uint8_t>& data_buffer);
		void _reassemble_request_packets(std::list<std::vector<uint8_t>>&& request_headers);
		void _reassemble_reponse_packets(std::list<std::vector<uint8_t>>&& response_headers);
		void _reassemble_reponse_packets_content(std::vector<uint8_t>& data);
		void _reassemble_reponse_packets_header(const std::vector<uint8_t>& data);

		void _process_http_packets(RequestPacket&& request_packet, ResponsePacket&& response_packet);
	public:
		PacketReassembler(Tins::TCPIP::Stream& stream);
		~PacketReassembler() = default;
	};
}
