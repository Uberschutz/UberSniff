#pragma once

#include <boost/asio.hpp>
#include <boost/thread/thread.hpp>
#include "api/Session.hpp"
#include "collector/DataBatch.hpp"

namespace ubersniff::api {
	class UberBack {
	public:
		struct Config {
			std::string service;
			std::string host;
			std::string port;
			std::string token;
			std::string userId;
		};

	private:
		const Config _config;
		boost::asio::io_context _io_context;
		boost::asio::executor_work_guard<boost::asio::io_context::executor_type> _work;
		boost::thread_group _worker_threads;
		
		std::string _convert_data_batch_to_json(const collector::DataBatches& data_batches) const;
		void _convert_texts_to_json(const std::unordered_map<std::string, int>& texts, std::stringstream& body) const;
		void _convert_images_to_json(const std::unordered_map<std::string, int>& images, std::stringstream& body) const;

		void _analyze_data_async(collector::DataBatches data_batches);
	public:
		explicit UberBack(const UberBack::Config& confi) noexcept;
		~UberBack();

		void analyze_data(collector::DataBatches data_batches);
	};
}
