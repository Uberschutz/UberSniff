#pragma once

#include <unordered_map>

namespace ubersniff::packet {
	/*
	* Represent a simplified HTTP request packet
	*/
	struct Request {
		std::string request;
		std::unordered_map<std::string, std::string> headers;

		std::string uri;
		std::string host;
		std::string path;
		std::string method;
	};
}
