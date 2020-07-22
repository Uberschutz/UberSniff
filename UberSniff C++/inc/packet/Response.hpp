#pragma once

#include <unordered_map>

namespace ubersniff::packet {
	/*
	* Enum of diffenrent content type that can be identified by the sniffer
	*/
	enum class ContentType {
		UNDEFINED,
		IMAGE,
		TEXT
	};

	/*
	* Represent a simplified HTTP response packet
	*/
	struct Response {
		std::string response;
		std::unordered_map<std::string, std::string> headers;

		std::string status_code;
		std::string status_message;

		std::string content;
		size_t content_length = 0;
		ContentType content_type = ContentType::UNDEFINED;
	};
}