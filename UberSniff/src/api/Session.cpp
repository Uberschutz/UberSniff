#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include "api/Session.hpp"

namespace ubersniff::api {
    // Report a failure
    void fail(boost::system::error_code ec, char const* what)
    {
        std::cerr << what << ": " << ec.message() << "\n";
    }

    Session::Session(boost::asio::io_context& ioc) :
        _ctx(ssl::context::sslv23_client),
        _resolver(ioc),
        _socket(ioc, 
            (_ctx.set_verify_mode(ssl::context::verify_peer),
                boost::certify::enable_native_https_server_verification(_ctx),
                _ctx))
    {
    }

    // Start the asynchronous operation
    void Session::send_post_async(Session::Request request)
    {
        // Set SNI Hostname (many hosts need this to handshake successfully)
        if (!SSL_set_tlsext_host_name(_socket.native_handle(), request.host)) {
            boost::system::error_code ec{ static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category() };
            throw boost::system::system_error{ ec };
        }

        // Set up an HTTP POST request message
        _request.version(11);
        _request.method(http::verb::post);
        _request.target(request.target);
        _request.set(http::field::host, request.host);
        _request.set(http::field::content_type, request.content_type);
        _request.set(http::field::content_length, request.content_length);
        _request.set("token", request.token);
        _request.body() = request.body;

        // Look up the domain name
        _resolver.async_resolve(
            request.host,
            request.port,
            std::bind(
                &Session::on_resolve,
                shared_from_this(),
                std::placeholders::_1,
                std::placeholders::_2
            ));
    }

    void Session::on_resolve(
            boost::system::error_code ec,
            tcp::resolver::results_type results)
    {
        if (ec)
            return fail(ec, "resolve");

        // Make the connection on the IP address we get from a lookup
        boost::asio::async_connect(
            _socket.next_layer(),
            results.begin(),
            results.end(),
            std::bind(
                &Session::on_connect,
                shared_from_this(),
                std::placeholders::_1
            ));
    }

    void Session::on_connect(boost::system::error_code ec)
    {
        if (ec)
            return fail(ec, "connect");

        // Perform the SSL handshake
        _socket.async_handshake(
            ssl::stream_base::client,
            std::bind(
                &Session::on_handshake,
                shared_from_this(),
                std::placeholders::_1));
    }

    void Session::on_handshake(boost::system::error_code ec)
    {
        if (ec)
            return fail(ec, "on_handshake");

        // Send the HTTP request to the remote host
        http::async_write(_socket, _request,
            std::bind(
                &Session::on_write,
                shared_from_this(),
                std::placeholders::_1,
                std::placeholders::_2
            ));
    }

    void Session::on_write(boost::system::error_code ec, std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if (ec)
            return fail(ec, "write");

        // Receive the HTTP response
        http::async_read(_socket, _buffer, _response,
            std::bind(
                &Session::on_read,
                shared_from_this(),
                std::placeholders::_1,
                std::placeholders::_2
            ));
    }

    void Session::on_read(boost::system::error_code ec, std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if (ec)
            return fail(ec, "read");

        // Gracefully close the stream
        _socket.async_shutdown(
            std::bind(
                &Session::on_shutdown,
                shared_from_this(),
                std::placeholders::_1));
    }

    void Session::on_shutdown(boost::system::error_code ec)
    {
        if (ec == boost::asio::error::eof)
            ec.assign(0, ec.category());
        if (ec)
            return fail(ec, "shutdown");
    }
}
