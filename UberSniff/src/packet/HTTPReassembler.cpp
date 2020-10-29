#include "packet/HTTPReassembler.hpp"

namespace ubersniff::packet {
	const boost::regex HTTPReassembler::_http_request_regex =
		boost::regex("^([\\w]+) ([^ ]+) HTTP/[^ ]+\r\n");
	const boost::regex HTTPReassembler::_http_response_regex =
		boost::regex("^HTTP/[^ ]+ ([\\d]+) ([\\w\\s]+)\r\n");

	HTTPReassembler::HTTPReassembler(collector::DataCollector& data_collector, const std::string& scheme) :
		_data_collector(data_collector),
		_scheme(scheme),
		_request_state(ReassembleState::NEXT),
		_response_state(ReassembleState::NEXT),
		_response_content_length(0),
		_response_is_chunked(true)
	{}

	/*
	** Push the client payload to the request data buffer
	**  and start the reassembling of the request packet
	*/
	void HTTPReassembler::push_client_payload(std::vector<uint8_t>& client_payload)
	{
		_request_buffer.insert(_request_buffer.end(), client_payload.begin(), client_payload.end());
		_reassemble_request();
	}

	/*
	** Push the server payload to the response data buffer
	**  and start the reassembling of the response packet
	*/
	void HTTPReassembler::push_server_payload(std::vector<uint8_t>& server_payload)
	{
		_response_buffer.insert(_response_buffer.end(), server_payload.begin(), server_payload.end());
		_reassemble_response();
	}

	/*
	** Reassembling request packet
	*/
	void HTTPReassembler::_reassemble_request()
	{
		// Loop until the buffer is empty
		while (true) {
			switch (_request_state) {
			case ReassembleState::NEXT:
				if (_search_http_request())
					_request_state = ReassembleState::HEADERS;
				else
					return;
				break;
			case ReassembleState::HEADERS:
				if (_reassemble_request_headers())
					_request_state = ReassembleState::BODY;
				else
					return;
				break;
			case ReassembleState::BODY:
				if (_reassemble_request_body())
					_request_state = ReassembleState::FINISHED;
				else
					return;
				break;
			case ReassembleState::FINISHED:
				_finish_request_reassembling();
				_request_state = ReassembleState::NEXT;
				break;
			}
		}
	}

	/*
	** Searchs the start of the http request in _request_buffer
	** When It finds the http request,
	**  it will erase (in _request_buffer) the data before the end of the http request message
	**
	** Returns true when it find a http resquest otherwise it return false
	*/
	bool HTTPReassembler::_search_http_request()
	{
		boost::match_results<std::deque<uint8_t>::iterator> matchs;

		// search the start of the next http request
		if (boost::regex_search(_request_buffer.begin(), _request_buffer.end(), matchs, _http_request_regex)) {
			// Init a new request
			_request = {};
			_request.request = std::move(std::string(matchs[0].begin(), matchs[0].end()));
			_request.method = std::move(std::string(matchs[1].begin(), matchs[1].end()));
			_init_http_request_uri(_request, std::move(std::string(matchs[2].begin(), matchs[2].end())));

			// remove datas before the end of the http request message
			_request_buffer.erase(_request_buffer.begin(),
				_request_buffer.begin() + matchs.position() + matchs[0].length());
			return true;
		} else {
			// No request detected
			_request_buffer.clear();
			return false;
		}
	}

	void HTTPReassembler::_init_http_request_uri(Request &request, std::string &&uri)
	{
		if (uri[0] == '/' || uri[0] == '*') {
			// Only the path is given, host will be given later in the headers
			request.path = uri;
		} else {
			// The entire uri is given
			// Check if the scheme is given
			if (uri.rfind(_scheme, 0) != std::string::npos) {
				request.uri = uri;
				// remove the scheme from uri
				uri = uri.substr(_scheme.size());
			} else {
				request.uri = _scheme + uri;
			}

			// Check if the path is given
			auto start_path_position = uri.find('/');
			if (start_path_position == uri.npos) {
				// there is no path
				request.host = _scheme + uri;
				request.path = "/";
			} else {
				// there is a path
				request.host = _scheme + uri.substr(0, start_path_position);
				request.path = uri.substr(start_path_position);
			}
		}
	}

	/*
	** Reassemble the headers of the http request
	** It will erase (in _request_buffer) the data corresponding to headers
	**
	** Returns true when it finishes the reassembling of headers otherwise it returns false
	*/
	bool HTTPReassembler::_reassemble_request_headers()
	{
		std::deque<uint8_t>::iterator position;

		while ((position = std::search(_request_buffer.begin(), _request_buffer.end(),
			_eol_delimiter.begin(), _eol_delimiter.end())) != _request_buffer.end()) {
			if (_request_buffer.begin() != position) {
				// get the header
				std::string header(_request_buffer.begin(), position + _eol_delimiter.size());
				// erase the header of the _request_buffer
				_request_buffer.erase(_request_buffer.begin(), position + _eol_delimiter.size());

				// get the position of the delimiter between the name and the value
				auto pos = std::search(header.begin(), header.end(), _header_value_delimiter.begin(), _header_value_delimiter.end());
				if (pos == header.end()) {
					// error whth the implementation of the protocol from the client
					return true;
				} else {
					std::string header_name(header.begin(), pos);
					std::string header_value(pos + _header_value_delimiter.size(), header.end() - 2);
					// parse the header
					_parse_request_header(header_name, header_value);
					// add the header
					_request.headers[std::move(header_name)] = std::move(header_value);
				}
		 	} else {
				// Empty Header receive: End of the list of headers
				// erase the last line of the _request_buffer
				_request_buffer.erase(_request_buffer.begin(), position + _eol_delimiter.size());
				return true;
			}
		}
		// incomplete headers
		return false;
	}

	/*
	** Add the header in the request and process for some specifics headers
	*/
	void HTTPReassembler::_parse_request_header(const std::string& header_name, const std::string& header_value)
	{
		// check the name of header
		if (header_name == "Host") {
			// Process for the host header
			// Add the scheme to the host if it is not given in the header and set the host
			_request.host = header_value.rfind(_scheme, 0) != std::string::npos ? header_value : _scheme + header_value;

			// Set the uri
			_request.uri = _request.host;
			// Add the path to the Uri if the path is not an wildcard
			if (_request.path != "*") {
				_request.uri += _request.path;
			}
		}
	}

	/*
	** Currently nothing to do for the body of the request but present for possible future implementation
	*/
	bool HTTPReassembler::_reassemble_request_body()
	{
		return true;
	}

	/*
	** Create an new http exchange with the reassembled request and push it in the exchanges queue
	*/
	void HTTPReassembler::_finish_request_reassembling()
	{
		// push the reassembled request
		_reassembled_request.push(std::move(_request));
		// reset _request
		_request = {};

		// try to send a reassembled exchange
		_send_exchange_to_collector();
	}

	/*
	** Reassembling response
	*/
	void HTTPReassembler::_reassemble_response()
	{
		// Loop until the buffer or the exchange queue is empty
		while (!_response_buffer.empty()) {
			switch (_response_state) {
			case ReassembleState::NEXT:
				if (_search_http_response())
					_response_state = ReassembleState::HEADERS;
				else
					return;
				break;
			case ReassembleState::HEADERS:
				if (_reassemble_response_headers())
					_response_state = ReassembleState::BODY;
				else
					return;
				break;
			case ReassembleState::BODY:
				if (_reassemble_response_body())
					_response_state = ReassembleState::FINISHED;
				else
					return;
				break;
			case ReassembleState::FINISHED:
				_finish_response_reassembling();
				_response_state = ReassembleState::NEXT;
				break;
			}
		}
	}

	/*
	** Searchs the start of the http response in _response_buffer
	** When It finds the http response,
	**  it will erase (in _response_buffer) the data before the start of http response
	*/
	bool HTTPReassembler::_search_http_response()
	{
		boost::match_results<std::deque<uint8_t>::iterator> matchs;

		// search the start of the next http response
		if (boost::regex_search(_response_buffer.begin(), _response_buffer.end(), matchs, _http_response_regex)) {
			// Init a new response
			_response = {};
			_response.response = std::move(std::string(matchs[0].begin(), matchs[0].end()));
			_response.status_code = std::move(std::string(matchs[1].begin(), matchs[1].end()));
			_response.status_message = std::move(std::string(matchs[2].begin(), matchs[2].end()));
			_response_content_length = 0;

			// remove datas before the end of the http response message
			_response_buffer.erase(_response_buffer.begin(),
				_response_buffer.begin() + matchs.position() + matchs[0].length());
			return true;
		} else {
			// No response detected
			_response_buffer.clear();
			return false;
		}
	}

	/*
	** Reassemble the headers of the http response
	** It will erase (in _response_buffer) the data corresponding to headers
	**
	** Returns true when it finishes the reassembling of headers otherwise it returns false
	*/
	bool HTTPReassembler::_reassemble_response_headers()
	{
		std::deque<uint8_t>::iterator position;

		while ((position = std::search(_response_buffer.begin(), _response_buffer.end(),
			_eol_delimiter.begin(), _eol_delimiter.end())) != _response_buffer.end()) {
			if (_response_buffer.begin() != position) {
				// get the header
				std::string header(_response_buffer.begin(), position + _eol_delimiter.size());
				// erase the header of the _response_buffer
				_response_buffer.erase(_response_buffer.begin(), position + _eol_delimiter.size());

				// get the position of the delimiter between the name and the value
				auto pos = std::search(header.begin(), header.end(), _header_value_delimiter.begin(), _header_value_delimiter.end());
				if (pos == header.end()) {
					// error whth the implementation of the protocol from the client
					return true;
				} else {
					std::string header_name(header.begin(), pos);
					std::string header_value(pos + _header_value_delimiter.size(), header.end() - 2);
					// parse the header
					_parse_response_header(header_name, header_value);
					// add the header
					_response.headers[std::move(header_name)] = std::move(header_value);
				}
			} else {
				// Empty Header receive: End of the list of headers
				// erase the last line of the _response_buffer
				_response_buffer.erase(_response_buffer.begin(), position + _eol_delimiter.size());
				return true;
			}
		}
		// incomplete headers
		return false;
	}

	/*
	** Add the header in the response and process for some specifics headers
	*/
	void HTTPReassembler::_parse_response_header(const std::string& header_name, const std::string& header_value)
	{
		// check the name of header
		if (header_name == "Content-Length") {
			// get the content length
			_response.content_length = std::atoi(header_value.c_str());
			_response_is_chunked = false;
		} else if (header_name == "Content-Type") {
			// get the content-type
			if (header_value.find("text/html") != std::string::npos) {
				_response.content_type = ContentType::TEXT;
			} else if (header_value.find("image") != std::string::npos) {
				_response.content_type = ContentType::IMAGE;
			}
		}
	}

	/*
	** Reassemble the body of the http response
	** It will erase (in _response_buffer) the data corresponding to headers
	**
	** Returns true when it finishes the reassembling of headers otherwise it returns false
	*/
	bool HTTPReassembler::_reassemble_response_body()
	{
		if (_response_is_chunked) {
			// Chunked body
			return _reassemble_response_body_chunked();
		} else {
			// With the header Content-Length
			return _reassemble_response_body_content_length();
		}
	}

	/*
	** Reassemble the body of the http response with content length
	** It will erase (in _response_buffer) the data corresponding to headers
	**
	** Returns true when it finishes the reassembling of headers otherwise it returns false
	*/
	bool HTTPReassembler::_reassemble_response_body_content_length()
	{
		size_t content_size = std::min(_response.content_length - _response_content_length, _response_buffer.size());
		// insert in body data from _response_buffer
		_response.content.insert(
			_response.content.end(),
			_response_buffer.begin(),
			_response_buffer.begin() + content_size);
		// update the current content length of body
		_response_content_length += content_size;
		// erase in _response_buffer the inserted data in body
		_response_buffer.erase(_response_buffer.begin(), _response_buffer.begin() + content_size);

		// return true if the body is reassembled or if content is > 30000
		return _response_content_length == _response.content_length
			|| _response_content_length >= 30000;
	}
 
	/*
	** Reassemble the body of the http response with chunked body
	** It will erase (in _response_buffer) the data corresponding to headers
	**
	** Returns true when it finishes the reassembling of headers otherwise it returns false
	*/
	bool HTTPReassembler::_reassemble_response_body_chunked()
	{
		auto position = std::search(_response_buffer.begin(), _response_buffer.end(),
			_eol_delimiter.begin(), _eol_delimiter.end());
		if (position == _response_buffer.end())
			return false;

		// get chunk size
		std::string chunk_size_s = std::string(_response_buffer.begin(), position);
		size_t chunk_size;
		try {
			chunk_size = std::stoul(chunk_size_s, nullptr, 16);
		}
		catch (std::exception&) {
			return true;
		}

		if (chunk_size == 0) {
			// end of chunked body, erase the chunk size in the buffer
			_response_buffer.erase(_response_buffer.begin(), position + _eol_delimiter.size());
			return true;
		} else {
			// check the buffer size
			if (_response_buffer.size() < chunk_size_s.size() + _eol_delimiter.size() + chunk_size) {
				// wait missing data
				return false;
			}
			// get chunk and add in response
			std::string chunk(position + _eol_delimiter.size(), position + _eol_delimiter.size() + chunk_size);
			_response.content += chunk;
			_response_content_length += chunk_size;
			// remove chunk in buffer
			_response_buffer.erase(_response_buffer.begin(), position + _eol_delimiter.size() + chunk_size);
			// return false if the current content length is < 30000
			return _response_content_length >= 30000;
		}
	}

	/*
	** Add the reassembled exchange to response queue
	*/
	void HTTPReassembler::_finish_response_reassembling()
	{
		// push the reassembled request
		_reassembled_response.push(std::move(_response));
		// reset _response
		_response = {};
		_response_content_length = 0;
		_response_is_chunked = true;

		// try to send a reassembled exchange
		_send_exchange_to_collector();
	}

	/*
	** Send a reassembled exchange to the data_collector
	** If an exchange is reassembled send it
	**  and remove the request and the response from the correponding queue
	*/
	void HTTPReassembler::_send_exchange_to_collector()
	{
		// quit if an exchange is not reassembled
		if (_reassembled_request.empty() || _reassembled_response.empty())
			return;

		// create exchange
		Exchange exchange = {
			std::move(_reassembled_request.front()),
			std::move(_reassembled_response.front())
		};

		// remove request and response from queue
		_reassembled_request.pop();
		_reassembled_response.pop();

		if (exchange.response.content_type == ContentType::TEXT) {
			_data_collector.collect_text_exchange(std::move(exchange));
		} else if (exchange.response.content_type == ContentType::IMAGE) {
			_data_collector.collect_image_exchange(std::move(exchange));
		}
	}
}
