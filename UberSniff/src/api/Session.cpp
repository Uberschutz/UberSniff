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
        _resolver(ioc),
        _socket(ioc)
    {}

    // Start the asynchronous operation
    void Session::send_post_async(Session::Request request)
    {
        // Set up an HTTP POST request message
        _request.version(11);
        _request.method(http::verb::post);
        _request.target(request.target);
        _request.set(http::field::host, request.host);
        _request.set(http::field::content_type, request.content_type);
        _request.set(http::field::content_length, request.content_length);
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
            _socket,
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

        // Write the message to standard out
        std::cout << _response << std::endl;

        // Gracefully close the socket
        _socket.shutdown(tcp::socket::shutdown_both, ec);

        // not_connected happens sometimes so don't bother reporting it.
        if (ec && ec != boost::system::errc::not_connected)
            return fail(ec, "shutdown");

        // If we get here then the connection is closed gracefully
    }
}
