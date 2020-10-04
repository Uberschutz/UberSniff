#include <iostream>
#include "sniffer/http/PacketReassembler.hpp"

namespace ubersniff::sniffer::http {
	PacketReassembler::PacketReassembler(Tins::TCPIP::Stream& stream, collector::DataCollector& data_collector):
		_data_collector(data_collector)
	{
		stream.client_data_callback(std::bind(&PacketReassembler::_on_client_data, this, std::placeholders::_1));
		stream.server_data_callback(std::bind(&PacketReassembler::_on_server_data, this, std::placeholders::_1));
	}

	PacketReassembler::~PacketReassembler()
	{}

	std::list<std::vector<uint8_t>> PacketReassembler::_extract_headers(std::vector<uint8_t>& data_buffer)
	{
		const std::vector<uint8_t> delimiter = { '\r', '\n' };
		std::list<std::vector<uint8_t>> headers;
		std::vector<uint8_t>::iterator pos;

		// extract headers
		while ((pos = std::search(data_buffer.begin(), data_buffer.end(), delimiter.begin(), delimiter.end()))
			!= data_buffer.end()) {
			std::vector<uint8_t> header(data_buffer.begin(), pos + delimiter.size());
			headers.push_back(std::move(header));
			data_buffer.erase(data_buffer.begin(), pos + delimiter.size());
		}
		return headers;
	}

	void PacketReassembler::_reassemble_reponse_packets_header(const std::vector<uint8_t>& data)
	{
		const std::vector<uint8_t> delimiter = { ':', ' ' };
		auto pos = std::search(data.begin(), data.end(), delimiter.begin(), delimiter.end());
		if (pos == data.end()) {
			// end of headers
			_is_reassembling_a_server_response_headers = false;
			_is_reassembling_a_response_packet_content = true;
			// call packet processing if it's an image
			if (_reassembling_response_packet.content_type == ContentType::IMAGE) {
				_process_http_packets({_request_packets.front(), _reassembling_response_packet});
			}
		} else {
			std::string header(data.begin(), pos);
			// remove "\r\n"
			std::string value(pos + delimiter.size(), data.end() - 2);
			_reassembling_response_packet.headers[header] = value;
			if (header == "Content-Length") {
				// get content length
				_reassembling_response_packet.content_length = std::atoi(value.c_str());
			} else if (header == "Content-Type") {
				// get content type
				if (value.find("text/html") != std::string::npos) {
					_reassembling_response_packet.content_type = ContentType::TEXT;
				} else if (value.find("image") != std::string::npos) {
					_reassembling_response_packet.content_type = ContentType::IMAGE;
				}
			}
		}
	}

	void PacketReassembler::_reassemble_reponse_packets_content(std::vector<uint8_t>& data)
	{
		auto content_left_size = _reassembling_response_packet.content_length - _response_packet_content_size;
		if (content_left_size < data.size()) {
			if (_reassembling_response_packet.content_type == ContentType::TEXT) {
				// save text content
				_reassembling_response_packet.content.insert(
					_reassembling_response_packet.content.end(),
					data.begin(),
					data.begin() + content_left_size);
			}
			_response_packet_content_size += content_left_size;
			data.erase(data.begin(), data.begin() + content_left_size);
		} else {
			if (_reassembling_response_packet.content_type == ContentType::TEXT) {
				// save text content
				_reassembling_response_packet.content.insert(
					_reassembling_response_packet.content.end(),
					data.begin(),
					data.end());
			}
			_response_packet_content_size += data.size();
			data.clear();
		}

		if (_reassembling_response_packet.content_length <= _response_packet_content_size) {
			// end of content
			_is_reassembling_a_response_packet_content = false;

			// call packet processing if it's text
			if (_reassembling_response_packet.content_type == ContentType::TEXT) {
				_process_http_packets({ _request_packets.front(), _reassembling_response_packet });
			}
			_request_packets.pop();
		}
	}

	void PacketReassembler::_reassemble_reponse_packets(std::list<std::vector<uint8_t>>&& response_headers)
	{
		std::smatch matchs;
		const std::regex http_request_regex("HTTP/[^ ]+ ([\\d]+) ([\\w\\s]+)\r\n");

		for (auto& it : response_headers) {
			if (_is_reassembling_a_server_response_headers) {
				// Reassemble headers of response
				_reassemble_reponse_packets_header(it);
			} else if (_is_reassembling_a_response_packet_content) {
				// Reassemble content of response
				_reassemble_reponse_packets_content(it);
			}
			if (!_is_reassembling_a_server_response_headers
				&& !_is_reassembling_a_response_packet_content) {
				std::string str(it.begin(), it.end());
				if (std::regex_match(str, matchs, http_request_regex)) {
					// New response packet identified
					_is_reassembling_a_server_response_headers = true;
					_response_packet_content_size = 0;
					_reassembling_response_packet = {};
					_reassembling_response_packet.response = str;
					_reassembling_response_packet.status_code = matchs[1].str();
					_reassembling_response_packet.status_message = matchs[2].str();
				}
			}
		}
		if (_is_reassembling_a_response_packet_content) {
			_reassemble_reponse_packets_content(_response_data_buffer);
		}
	}

	void PacketReassembler::_reassemble_request_packets(std::list<std::vector<uint8_t>>&& request_headers)
	{
		for (auto& it : request_headers) {
			if (_is_reassembling_a_request_packet) {
				const std::vector<uint8_t> delimiter = { ':', ' ' };
				auto pos = std::search(it.begin(), it.end(), delimiter.begin(), delimiter.end());
				if (pos == it.end()) {
					_is_reassembling_a_request_packet = false;
					_request_packets.push(_reassembling_request_packet);
				} else {
					std::string header(it.begin(), pos);
					// remove "\r\n"
					std::string value(pos + delimiter.size(), it.end() - 2);
					_reassembling_request_packet.headers[header] = value;
				}
			} else {
				std::smatch matchs;
				const std::regex http_request_regex("([\\w]+) ([^ ]+) HTTP/[^ ]+\r\n");
				std::string str(it.begin(), it.end());
				// Search http request
				if (std::regex_match(str, matchs, http_request_regex)) {
					_reassembling_request_packet = {};
					_is_reassembling_a_request_packet = true;
					_reassembling_request_packet.request = str;
					_reassembling_request_packet.method = matchs[1].str();
					std::string uri = matchs[2].str();
					if (uri[0] == '/') {
						_reassembling_request_packet.path = uri;
					} else if (uri[0] == '*') {
						_reassembling_request_packet.path = "/";
					} else {
						if (uri.rfind("http://", 0) != std::string::npos) {
							_reassembling_request_packet.uri = uri;
							// remove http://
							uri = uri.substr(8);
						} else {
							_reassembling_request_packet.uri = "http://" + uri;
						}
						auto pos_host_end = uri.find('/');
						if (pos_host_end == uri.npos) {
							// no path
							_reassembling_request_packet.host = "http://" + uri;
							_reassembling_request_packet.path = "/";
						} else {
							_reassembling_request_packet.host = "http://" + uri.substr(0, pos_host_end);
							_reassembling_request_packet.path = uri.substr(pos_host_end);
						}
					}
				}
			}
		}
	}

	void PacketReassembler::_process_http_packets(Exchanges exchanges)
	{
		std::cout << std::string(100, '*') << std::endl;

		// print Url
		if (!exchanges.request.uri.size() && exchanges.request.headers.count("Host")) {
			if (exchanges.request.headers["Host"].rfind("http://", 0) != std::string::npos) {
				exchanges.request.host = exchanges.request.headers["Host"];
				exchanges.request.uri = exchanges.request.host;
			} else {
				exchanges.request.host = "http://" + exchanges.request.headers["Host"];
				exchanges.request.uri = exchanges.request.host;
			}
			if (exchanges.request.path != "*") {
				exchanges.request.uri += exchanges.request.path;
			}
		}
		std::cout << "Received a packet from \"" << exchanges.request.uri
			<< "\" with status code " << exchanges.response.status_code << std::endl;

		// send exchanges to the DataCollector
		if (exchanges.response.content_type == ContentType::TEXT) {
			_data_collector.collect_text_exchange(std::move(exchanges));
		} else if (exchanges.response.content_type == ContentType::IMAGE) {
			_data_collector.collect_image_exchange(std::move(exchanges));
		}

		std::cout << std::string(100, '*') << std::endl;
		std::cout << std::endl;
	}


	void PacketReassembler::_on_server_data(Tins::TCPIP::Stream& stream)
	{
		// quit if no request
		if (!_request_packets.size()) {
			return;
		}

		// copy server_payload of the packet to the PacketReassembler
		_response_data_buffer.insert(_response_data_buffer.end(), stream.server_payload().begin(), stream.server_payload().end());

		//extract headers
		auto response_headers = std::move(_extract_headers(_response_data_buffer));
		_reassemble_reponse_packets(std::move(response_headers));
	}

	void PacketReassembler::_on_client_data(Tins::TCPIP::Stream& stream)
	{
		// copy client_payload of the packet to the PacketReassembler
		_request_data_buffer.insert(_request_data_buffer.end(), stream.client_payload().begin(), stream.client_payload().end());

		//extract headers
		auto request_headers = std::move(_extract_headers(_request_data_buffer));
		_reassemble_request_packets(std::move(request_headers));
	}
}
