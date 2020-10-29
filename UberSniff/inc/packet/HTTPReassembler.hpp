#pragma once

#include <array>
#include <boost/regex.hpp>
#include "collector/DataCollector.hpp"
#include "packet/Exchange.hpp"
#include "packet/Response.hpp"
#include "packet/Request.hpp"

namespace ubersniff::packet {
	class HTTPReassembler {
		using Exchanges = ubersniff::packet::Exchange;
		using Response = ubersniff::packet::Response;
		using Request = ubersniff::packet::Request;
		using ContentType = ubersniff::packet::ContentType;

		enum class ReassembleState {
			NEXT = 0,
			HEADERS,
			BODY,
			FINISHED
		};

		static const boost::regex _http_request_regex;
		static const boost::regex _http_response_regex;
		// End of line delimiter
		static constexpr std::array<uint8_t, 2> _eol_delimiter{ '\r', '\n' };
		static constexpr std::array<char, 2> _header_value_delimiter{ ':', ' ' };

		const std::string _scheme;

		collector::DataCollector& _data_collector;

		std::deque<uint8_t> _request_buffer;
		std::deque<uint8_t> _response_buffer;

		Request _request;
		Response _response;
		size_t _response_content_length;
		bool _response_is_chunked;

		std::queue<Request> _reassembled_request;
		std::queue<Response> _reassembled_response;

		ReassembleState _request_state;
		ReassembleState _response_state;

		void _reassemble_request();
		bool _search_http_request();
		bool _reassemble_request_headers();
		bool _reassemble_request_body();
		void _finish_request_reassembling();
		void _init_http_request_uri(Request& request, std::string &&uri);
		void _parse_request_header(const std::string &, const std::string &);

		void _reassemble_response();
		bool _search_http_response();
		bool _reassemble_response_headers();
		bool _reassemble_response_body();
		void _finish_response_reassembling();
		void _parse_response_header(const std::string &, const std::string &);
		bool _reassemble_response_body_content_length();
		bool _reassemble_response_body_chunked();

		void _send_exchange_to_collector();
	public:
		HTTPReassembler(collector::DataCollector &_data_collector, const std::string &scheme);
		~HTTPReassembler() = default;

		void push_client_payload(std::vector<uint8_t>& client_payload);
		void push_server_payload(std::vector<uint8_t>& server_payload);
	};
}
