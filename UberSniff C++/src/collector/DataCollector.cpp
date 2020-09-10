#include <iostream>
#include <regex>
#include "collector/DataCollector.hpp"

namespace ubersniff::collector {
	void DataCollector::_push_image_exchange(packet::Exchange exchange)
	{
		std::lock_guard<std::mutex> lock(_mutex_image_exchanges_queue);
		_image_exchanges_queue.push(std::move(exchange));
	}

	bool DataCollector::_pop_image_exchange(packet::Exchange& exchange) noexcept
	{
		std::lock_guard<std::mutex> lock(_mutex_image_exchanges_queue);

		if (_image_exchanges_queue.empty())
			return false;
		exchange = _image_exchanges_queue.front();
		_image_exchanges_queue.pop();
		return true;
	}

	void DataCollector::_push_text_exchange(packet::Exchange exchange)
	{
		std::lock_guard<std::mutex> lock(_mutex_text_exchanges_queue);
		_text_exchanges_queue.push(std::move(exchange));
	}

	bool DataCollector::_pop_text_exchange(packet::Exchange& exchange) noexcept
	{
		std::lock_guard<std::mutex> lock(_mutex_text_exchanges_queue);

		if (_text_exchanges_queue.empty())
			return false;
		exchange = _text_exchanges_queue.front();
		_text_exchanges_queue.pop();
		return true;
	}

	bool DataCollector::process_next_image_exchange() noexcept
	{
		packet::Exchange exchange;
		if (!_pop_image_exchange(exchange))
			// no exchange to process
			return false;

		std::string referer;
		// get referer
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

		std::lock_guard<std::mutex> lock(_mutex_data_batches);
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
		return true;
	}

	void DataCollector::_remove_multiple_space(std::string& str) const noexcept
	{
		std::string::iterator new_end = std::unique(str.begin(), str.end(),
			[](char lhs, char rhs) {
				return (lhs == rhs) && (lhs == ' ');
			});
		str.erase(new_end, str.end());
	}

	void DataCollector::_remove_html_tag(std::string& str) const noexcept
	{
		str = std::regex_replace(str, std::regex("<script>.*</script>"), "");
		str = std::regex_replace(str, std::regex("<object>.*</object>"), "");
		str = std::regex_replace(str, std::regex("<style>.*</style>"), "");
		str = std::regex_replace(str, std::regex("<noscript>.*</noscript>"), "");
		str = std::regex_replace(str, std::regex("<.*>"), "");
	}

	std::list<std::string> DataCollector::_get_list_of_content(std::string content) const noexcept
	{
		content.erase(std::remove(content.begin(), content.end(), '\r'), content.end());
		std::list<std::string> list_content;
		std::string delimiter = "\n";

		size_t pos = 0;
		std::string content_line;
		while ((pos = content.find(delimiter)) != std::string::npos) {
			content_line = content.substr(0, pos);
			content_line = std::regex_replace(content_line, std::regex("^ +"), "");
			content_line = std::regex_replace(content_line, std::regex(" +$"), "");
			if (content_line.size()) {
				list_content.push_back(content_line);
			}
			content.erase(0, pos + delimiter.length());
		}
		return list_content;
	}

	bool DataCollector::process_next_text_exchange() noexcept
	{
		// get the next exchange
		packet::Exchange exchange;
		if (!_pop_text_exchange(exchange))
			// no exchange to process
			return false;

		auto& uri = exchange.request.host;
		auto& content = exchange.response.content;

		// clean the html content
		_remove_html_tag(content);
		_remove_multiple_space(content);
		auto content_list = _get_list_of_content(content);

		// quit if no content
		if (!content_list.size()) {
			return true;
		}

		std::lock_guard<std::mutex> lock(_mutex_data_batches);
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
		return true;
	}

	bool DataCollector::process_next_exchanges() noexcept
	{
		bool is_text_processed = process_next_text_exchange();
		bool is_image_processed = process_next_image_exchange();
		return is_text_processed || is_image_processed;
	}

	void DataCollector::collect_image_exchange(packet::Exchange exchange)
	{
		std::cout << "\tIt is an image" << std::endl;
		_push_image_exchange(std::move(exchange));
	}

	void DataCollector::collect_text_exchange(packet::Exchange exchange)
	{
		std::cout << "\tIt is html content" << std::endl;
		_push_text_exchange(std::move(exchange));
	}

	void DataCollector::dump() noexcept
	{
		std::lock_guard<std::mutex> lock(_mutex_data_batches);
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

	DataBatches DataCollector::extract_data_batches()
	{
		std::lock_guard<std::mutex> lock(_mutex_data_batches);
		// copy dataBatches
		DataBatches data_batches = _data_batches;
		// clear dataBatches
		_data_batches.clear();
		// return the copy
		return data_batches;
	}
}
