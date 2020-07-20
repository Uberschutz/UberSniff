#pragma once

namespace ubersniff::sniffer {
	class ISniffer {
	public:
		virtual ~ISniffer() = default;

		virtual void start_sniffing() = 0;
		virtual void stop_sniffing() = 0;
	};
}
