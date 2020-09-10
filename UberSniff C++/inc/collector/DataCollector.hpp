#pragma once

#include <mutex>
#include <queue>
#include "packet/Exchange.hpp"
#include "collector/DataBatch.hpp"

namespace ubersniff::collector {
	class DataCollector {
		std::mutex _mutex_data_batches;
		DataBatches _data_batches;

		std::mutex _mutex_text_exchanges_queue;
		std::queue<packet::Exchange> _text_exchanges_queue;

		std::mutex _mutex_image_exchanges_queue;
		std::queue<packet::Exchange> _image_exchanges_queue;

		void _push_image_exchange(packet::Exchange exchange);
		bool _pop_image_exchange(packet::Exchange& exchange) noexcept;

		void _push_text_exchange(packet::Exchange exchange);
		bool _pop_text_exchange(packet::Exchange& exchange) noexcept;

		void _remove_html_tag(std::string& str) const noexcept;
		void _remove_multiple_space(std::string& str)  const noexcept;
		std::list<std::string> _get_list_of_content(std::string str) const noexcept;
	public:
		DataCollector() = default;
		~DataCollector() = default;

		/* 
		** process_next_*_exchange will process the next exchange in the queue
		** process_next_exchanges will process the next exchange of each queue
		** return true if an exchange has been processed
		** return false if there are no exchange to process
		*/
		bool process_next_image_exchange() noexcept;
		bool process_next_text_exchange() noexcept;
		bool process_next_exchanges() noexcept;

		void collect_image_exchange(packet::Exchange exchange);
		void collect_text_exchange(packet::Exchange exchange);

		void dump() noexcept;
		DataBatches extract_data_batches();
	};
}
