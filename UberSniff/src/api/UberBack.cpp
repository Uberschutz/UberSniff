#include <sstream>
#include "api/UberBack.hpp"

namespace ubersniff::api {
	UberBack::UberBack(const UberBack::Config &config) noexcept :
		_io_context(),
		_work(boost::asio::make_work_guard(_io_context)),
		_worker_threads(),
		_config(config)
	{
		for (int x = 0; x < 2; ++x)
		{
			_worker_threads.create_thread(
				boost::bind(&boost::asio::io_service::run, &_io_context)
			);
		}
	}

	UberBack::~UberBack()
	{
		_work.reset();
		_worker_threads.join_all();
	}

	void UberBack::analyze_data(collector::DataBatches data_batches)
	{
		if (data_batches.size() == 0)
			return; // no data

		boost::asio::post(_io_context, std::bind(&UberBack::_analyze_data_async, this, std::move(data_batches)));
	}

	void UberBack::_analyze_data_async(collector::DataBatches data_batches)
	{
		std::string body = _convert_data_batch_to_json(data_batches);
		Session::Request request;

		request.host = _config.host.c_str();
		request.port = _config.port.c_str();
		request.token = _config.token.c_str();
		request.target = "/data";
		request.content_type = "application/json";
		request.body = body.c_str();
		request.content_length = body.size();
		std::make_shared<Session>(_io_context)->send_post_async(std::move(request));
	}

	void UberBack::_convert_texts_to_json(const std::unordered_map<std::string, int>& texts, std::stringstream& body) const
	{
		if (texts.empty())
			return;
		bool first_text = true;
		body << ",\"texts\":[";
		for (auto& text : texts) {
			if (first_text)
				first_text = false;
			else
				body << ",";
			body << "{";
			body << "\"content\":\"" << text.second << "\",";
			body << "\"nb\":" << text.second;
			body << "}";
		}
		body << "]";
	}

	void UberBack::_convert_images_to_json(const std::unordered_map<std::string, int>& images, std::stringstream& body) const
	{
		if (images.empty())
			return;
		bool first_image = true;
		body << ",\"images\":[";
		for (auto& image : images) {
			if (first_image)
				first_image = false;
			else
				body << ",";
			body << "{";
			body << "\"content\":\"" << image.second << "\",";
			body << "\"nb\":" << image.second;
			body << "}";
		}
		body << "]";
	}

	std::string UberBack::_convert_data_batch_to_json(const collector::DataBatches& data_batches) const
	{
		std::stringstream body;
		body << "{";
		body << "\"userId\": \"" << _config.userId << "\",";
		body << "\"service\": \"" << _config.service << "\",";
		body << "\"dataBatches\": [";
		bool first_batch = true;
		// convert batches
		for (auto& data_batch : data_batches) {
			if (first_batch)
				first_batch = false;
			else
				body << ",";
			body << "{";
			body << "\"urlSrc\": \"" << data_batch.first << "\"";
			// convert texts
			_convert_texts_to_json(data_batch.second.texts, body);
			// convert images
			_convert_images_to_json(data_batch.second.images, body);
			body << "}";
		}
		body << "]";
		body << "}";
		return std::move(body.str());
	}
}
