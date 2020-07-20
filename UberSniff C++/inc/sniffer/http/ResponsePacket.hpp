#pragma once

#include <unordered_map>

namespace ubersniff::sniffer::http {
	enum class ContentType {
		UNDEFINED,
		IMAGE,
		TEXT
	};

	struct ResponsePacket {
		std::string response;
		std::unordered_map<std::string, std::string> headers;

		std::string status_code;
		std::string status_message;

		std::string content;
		size_t content_length;
		ContentType content_type;
	};
}