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

	std::string UberBack::_convert_data_batch(const collector::DataBatches &data_batches) const
	{
		std::stringstream body;
		body << "userId=" << _config.userId << "&token=" << _config.token << "&service=" << _config.service;

		int batch_idx = 0;
		for (auto& data_batch : data_batches) {
			body << "&dataBatches[" << batch_idx << "][urlSrc]=" << data_batch.first;

			// convert images
			int image_idx = 0;
			for (auto& image : data_batch.second.images) {
				body << "&dataBatches[" << batch_idx << "][images][" << image_idx << "][content]=" << image.first;
				body << "&dataBatches[" << batch_idx << "][images][" << image_idx << "][nb]=" << image.second;
				++image_idx;
			}

			// convert texts
			int text_idx = 0;
			for (auto& text : data_batch.second.texts) {
				body << "&dataBatches[" << batch_idx << "][texts][" << text_idx << "][content]=" << text.first;
				body << "&dataBatches[" << batch_idx << "][texts][" << text_idx << "][nb]=" << text.second;
				++text_idx;
			}

			++batch_idx;
		}
		return body.str();
	}

	void UberBack::_analyze_data_async(collector::DataBatches data_batches)
	{
		std::string body = _convert_data_batch(data_batches);
		Session::Request request;

		request.host = _config.host.c_str();
		request.port = _config.port.c_str();
		request.target = "/data";
		request.content_type = "application/x-www-form-urlencoded";
		request.body = body.c_str();
		request.content_length = body.size();
		std::make_shared<Session>(_io_context)->send_post_async(std::move(request));
	}


	void UberBack::analyze_data(collector::DataBatches data_batches)
	{
		if (data_batches.size() == 0)
			return; // no data

		boost::asio::post(_io_context, std::bind(&UberBack::_analyze_data_async, this, std::move(data_batches)));
	}
}
