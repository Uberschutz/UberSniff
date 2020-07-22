#include <iostream>
#include <regex>
#include "collector/DataCollector.hpp"

namespace ubersniff::collector {
	void DataCollector::dump() const
	{
		std::cout << std::string(100, '-') << std::endl;
		std::cout << "\tData Collected:" << std::endl;
		for (const auto& it : _data_batches) {
			std::cout << "{" << std::endl;
			std::cout << "\tUrlSrc: " << it.first << "," << std::endl;
			std::cout << "\tDataBatch: {" << std::endl;

			if (it.second.images.size()) {
				std::cout << "\t\timages: {" << std::endl;
				for (const auto& image : it.second.images) {
					std::cout << "\t\t\tdata: \"" << image.first << "\"" << std::endl;
					std::cout << "\t\t\tnb: " << image.second << std::endl;
				}
				std::cout << "\t\t}" << std::endl;
			}
			if (it.second.texts.size()) {
				std::cout << "\t\ttexts: {" << std::endl;
				for (const auto& text : it.second.texts) {
					std::cout << "\t\t\tdata: \"" << text.first << "\"" << std::endl;
					std::cout << "\t\t\tnb: " << text.second << std::endl;
				}
				std::cout << "\t\t}" << std::endl;
			}
			std::cout << "\t}" << std::endl;
			std::cout << "}" << std::endl;
		}

		std::cout << std::string(100, '-') << std::endl;
		std::cout << std::endl;
	}

	void DataCollector::_push_image_exchanges(packet::Exchanges exchanges)
	{
		std::lock_guard<std::mutex> lock(_mutex_image_exchanges_queue);
		_image_exchanges_queue.push(std::move(exchanges));
	}

	bool DataCollector::_pop_image_exchanges(packet::Exchanges& exchanges)
	{
		std::lock_guard<std::mutex> lock(_mutex_image_exchanges_queue);

		if (_image_exchanges_queue.empty())
			return false;
		exchanges = _image_exchanges_queue.front();
		_image_exchanges_queue.pop();
		return true;
	}

	void DataCollector::_push_text_exchanges(packet::Exchanges exchanges)
	{
		std::lock_guard<std::mutex> lock(_mutex_text_exchanges_queue);
		_text_exchanges_queue.push(std::move(exchanges));
	}

	bool DataCollector::_pop_text_exchanges(packet::Exchanges& exchanges)
	{
		std::lock_guard<std::mutex> lock(_mutex_text_exchanges_queue);

		if (_text_exchanges_queue.empty())
			return false;
		exchanges = _text_exchanges_queue.front();
		_text_exchanges_queue.pop();
		return true;
	}

	void DataCollector::process_next_image_exchanges()
	{
		packet::Exchanges exchange;
		_pop_image_exchanges(exchange);

		std::string referer;
		if (exchange.request.headers.count("Referer")) {
			referer = exchange.request.headers.at("Referer");
			auto pos_host_end = referer.find('/', 8);
			if (pos_host_end != referer.npos) {
				referer = referer.substr(0, pos_host_end);
			}
		} else {
			referer = exchange.request.uri;
		}
		auto& uri = exchange.request.uri;

		// create the batch if it not exist for the uri
		if (!_data_batches.count(referer)) {
			_data_batches[referer] = {};
		}

		// add data in the batches
		if (!_data_batches[referer].images.count(uri)) {
			_data_batches[referer].images[uri] = 1;
		} else {
			++_data_batches[referer].images[uri];
		}
	}

	void remove_multiple_space(std::string& str)
	{
		std::string::iterator new_end = std::unique(str.begin(), str.end(),
			[](char lhs, char rhs) {
				return (lhs == rhs) && (lhs == ' ');
			});
		str.erase(new_end, str.end());
	}

	void remove_html_tag(std::string& str)
	{
		str = std::regex_replace(str, std::regex("<script>.*</script>"), "");
		str = std::regex_replace(str, std::regex("<object>.*</object>"), "");
		str = std::regex_replace(str, std::regex("<style>.*</style>"), "");
		str = std::regex_replace(str, std::regex("<noscript>.*</noscript>"), "");
		str = std::regex_replace(str, std::regex("<.*>"), "");
	}

	std::list<std::string> get_list_of_content(std::string str)
	{
		str.erase(std::remove(str.begin(), str.end(), '\r'), str.end());
		std::list<std::string> list_content;
		std::string delimiter = "\n";

		size_t pos = 0;
		std::string content;
		while ((pos = str.find(delimiter)) != std::string::npos) {
			content = str.substr(0, pos);
			content = std::regex_replace(content, std::regex("^ +"), "");
			content = std::regex_replace(content, std::regex(" +$"), "");
			if (content.size()) {
				list_content.push_back(content);
			}
			str.erase(0, pos + delimiter.length());
		}
		return list_content;
	}

	void DataCollector::process_next_text_exchanges()
	{
		packet::Exchanges exchange;
		_pop_text_exchanges(exchange);

		auto& uri = exchange.request.host;

		auto& content = exchange.response.content;
		remove_html_tag(content);
		remove_multiple_space(content);
		auto content_list = get_list_of_content(content);

		// quit if no content
		if (!content_list.size()) {
			return;
		}

		// create the batch if it not exist for the uri
		if (!_data_batches.count(uri)) {
			_data_batches[uri] = {};
		}

		// add data in the batches
		for (auto& it : content_list) {
			if (!_data_batches[uri].texts.count(it)) {
				_data_batches[uri].texts[it] = 1;
			} else {
				++_data_batches[uri].texts[it];
			}
		}
	}

	void DataCollector::collect_image_exchanges(packet::Exchanges exchange)
	{
		std::cout << "\tIt is an image" << std::endl;
		_push_image_exchanges(std::move(exchange));

		// temporary code
		process_next_image_exchanges();
	}

	void DataCollector::collect_text_exchanges(packet::Exchanges exchange)
	{
		std::cout << "\tIt is html content" << std::endl;
		_push_text_exchanges(std::move(exchange));

		// temporary code
		process_next_text_exchanges();
	}
}
