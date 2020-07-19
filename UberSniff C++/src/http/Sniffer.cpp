#include <iostream>
#include <pcap.h>
#include "http/Sniffer.hpp"

namespace ubershutz::sniffer::http {
	Sniffer::Sniffer(const std::string& interface_name) :
		_sniffer_config(),
		_sniffer(interface_name,
			(_sniffer_config.set_filter("tcp port 80"),
				_sniffer_config.set_timeout(TIMEOUT),
				_sniffer_config)),
		_stream_follower()
	{
		_stream_follower.new_stream_callback(std::bind(&Sniffer::_on_new_connection, this, std::placeholders::_1));
	}

	Sniffer::~Sniffer()
	{
		// stop the sniffer if it is running
		if (_is_sniffing) {
			_is_sniffing = false;
			_sniffer_thread.join();
		}
	}

	void Sniffer::_on_new_connection(Tins::TCPIP::Stream& stream)
	{
		auto stream_id = Tins::TCPIP::StreamIdentifier::make_identifier(stream);
		_packet_reassemblers[stream_id] = std::unique_ptr<PacketReassembler>(new PacketReassembler(stream));

		// erase PacketReassembler when the stream closed properly
		stream.stream_closed_callback([&](Tins::TCPIP::Stream& stream) {
			_packet_reassemblers.erase(Tins::TCPIP::StreamIdentifier::make_identifier(stream));
		});
		// erase PacketReassembler when the stream closed with an error
		_stream_follower.stream_termination_callback([&](Tins::TCPIP::Stream& stream, Tins::TCPIP::StreamFollower::TerminationReason) {
			_packet_reassemblers.erase(Tins::TCPIP::StreamIdentifier::make_identifier(stream));
		});
	}

	void Sniffer::start_sniffing()
	{
		if (_is_sniffing) {
			return;
		}

		_is_sniffing = true;
		// run the sniffer in other thread
		_sniffer_thread = std::thread([&]() {
			while (_is_sniffing) {
#ifdef _WIN32 // Set timeout for the sniffer for windows
				auto event_h = pcap_getevent(_sniffer.get_pcap_handle());
				auto result = WaitForSingleObject(event_h, (DWORD)TIMEOUT);
				if (result == WAIT_OBJECT_0) {
#endif // _WIN32
					Tins::Packet packet(_sniffer.next_packet());
					_stream_follower.process_packet(packet);
#ifdef _WIN32
				}
#endif // _WIN32
			}
		});
	}

	void Sniffer::stop_sniffing()
	{
		if (!_is_sniffing) {
			return;
		}
		_is_sniffing = false;
		_sniffer_thread.join();
	}
}
