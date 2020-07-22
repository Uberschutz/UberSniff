#pragma once

#include <mutex>
#include <queue>
#include "packet/Exchanges.hpp"
#include "collector/DataBatch.hpp"

namespace ubersniff::collector {
	class DataCollector {
		DataBatches _data_batches;

		std::mutex _mutex_text_exchanges_queue;
		std::queue<packet::Exchanges> _text_exchanges_queue;

		std::mutex _mutex_image_exchanges_queue;
		std::queue<packet::Exchanges> _image_exchanges_queue;

		void _push_image_exchanges(packet::Exchanges exchanges);
		bool _pop_image_exchanges(packet::Exchanges& exchanges);

		void _push_text_exchanges(packet::Exchanges exchanges);
		bool _pop_text_exchanges(packet::Exchanges& exchanges);
	public:
		DataCollector() = default;
		~DataCollector() = default;

		void process_next_image_exchanges();
		void process_next_text_exchanges();


		void collect_image_exchanges(packet::Exchanges exchange);
		void collect_text_exchanges(packet::Exchanges exchange);

		void dump() const;
	};
}
