#pragma once

namespace ubersniff::sniffer {
	class ISniffer {
	public:
		virtual ~ISniffer() = default;

		virtual bool is_sniffing() = 0;
		virtual void start_sniffing() = 0;
		virtual void stop_sniffing() = 0;

		virtual void change_interface(const std::string& interface_name) = 0;
	};
}
