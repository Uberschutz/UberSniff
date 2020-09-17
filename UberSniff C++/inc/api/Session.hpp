#pragma once

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>

namespace ubersniff::api {
	using tcp = boost::asio::ip::tcp;
	namespace http = boost::beast::http;

	class Session: public std::enable_shared_from_this<Session> {
	public:
		struct Request {
			const char* host;
			const char* port;
			const char* target;
			const char* content_type;
			const char* body;
			size_t content_length;
		};

	private:
		tcp::resolver _resolver;
        tcp::socket _socket;
        boost::beast::flat_buffer _buffer; // (Must persist between reads)
		http::request<http::string_body> _request;
		http::response<http::string_body> _response;

	public:
		explicit Session(boost::asio::io_context& ioc);
		~Session() = default;

		void on_read(boost::system::error_code ec, std::size_t bytes_transferred);
		void on_write(boost::system::error_code ec, std::size_t bytes_transferred);
		void on_connect(boost::system::error_code ec);
		void on_resolve(boost::system::error_code ec, tcp::resolver::results_type results);
		void send_post_async(Session::Request request);
	};
}
