#pragma once

#include "packet/Response.hpp"
#include "packet/Request.hpp"

namespace ubersniff::packet {
	/*
	* Represent the HTTP request/response exchanges
	*/
	struct Exchange {
		Request request;
		Response response;
	};
}
