#pragma once

#include <pugixml.hpp>
#include "api/UberBack.hpp"

namespace ubersniff::config {
	class Config {
		ubersniff::api::UberBack::Config _uberback_config;

	public:
		Config(const std::string& filename);
		virtual ~Config() = default;

		const ubersniff::api::UberBack::Config &get_uberback_config() const noexcept;
	};
}
