#include <stdexcept>
#include "config/Config.hpp"

namespace ubersniff::config {
	Config::Config(const std::string& filename)
	{
        // open xml file
		pugi::xml_document doc;
        if (!doc.load_file(filename.c_str()))
            throw std::invalid_argument("Can not open the given file");
        
        // get config node
        pugi::xml_node config = doc.child("Config");
        if (!config)
            throw std::invalid_argument("It's not a config file");

        // get uberback config node
        pugi::xml_node uberback_config = config.child("Uberback");
        if (!config)
            throw std::invalid_argument("Doesn't contain Uberback config");

        // get config for Uberback API
        _uberback_config.host = uberback_config.child_value("Host");
        _uberback_config.port = uberback_config.child_value("Port");
        _uberback_config.service = uberback_config.child_value("Service");
        _uberback_config.token = uberback_config.child_value("Token");
        _uberback_config.userId = uberback_config.child_value("UserId");

        // check config for Uberback API
        if (_uberback_config.host.empty())
            throw std::invalid_argument("Invalid Uberback config: No Host provided");
        if (_uberback_config.port.empty())
            throw std::invalid_argument("Invalid Uberback config: No Port provided");
        if (_uberback_config.service.empty())
            throw std::invalid_argument("Invalid Uberback config: No Service provided");
        if (_uberback_config.token.empty())
            throw std::invalid_argument("Invalid Uberback config: No Token provided");
        if (_uberback_config.userId.empty())
            throw std::invalid_argument("Invalid Uberback config: No UserId provided");
    }

    const ubersniff::api::UberBack::Config& Config::get_uberback_config() const noexcept
    {
        return _uberback_config;
    }
}
