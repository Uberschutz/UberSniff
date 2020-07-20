#pragma once

#include <unordered_map>

namespace ubersniff::sniffer::http {
	struct RequestPacket {
		std::string request;
		std::unordered_map<std::string, std::string> headers;

		std::string method;
		std::string url;
	};
}