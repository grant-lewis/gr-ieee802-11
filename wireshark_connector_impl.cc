#include "wireshark_connector_impl.h"
#include <foo/wireshark_connector.h>
#include <pmt/pmt.h>
#include <gnuradio/io_signature.h>
#include <gnuradio/block_detail.h>

#include <chrono>
#include <iostream>
#include <iomanip>

#include <vector>
#include <complex>


using namespace gr::foo;


#define dout d_debug && std::cout

wireshark_connector_impl::wireshark_connector_impl(LinkType type, bool debug) :
	block ("wireshark_connector",
			gr::io_signature::make(0, 0, 0),
			gr::io_signature::make(1, 1, sizeof(uint8_t))),
			d_msg_offset(0),
			d_debug(debug),
			d_link(type) {

	message_port_register_in(pmt::mp("in"));

	d_msg_len = sizeof(pcap_file_hdr);
	d_msg = reinterpret_cast<char*>(std::malloc(d_msg_len));

	pcap_file_hdr *hdr   = reinterpret_cast<pcap_file_hdr*>(d_msg);
	hdr->magic_number  = 0xa1b2c3d4;
	hdr->version_major = 2;
	hdr->version_minor = 4;
	hdr->thiszone      = 0;
	hdr->sigfigs       = 0;
	hdr->snaplen       = 65535;
	hdr->network       = d_link;
}

void
wireshark_connector_impl::handle_pdu(pmt::pmt_t pdu) {

	// get current time
	auto tp_now = std::chrono::system_clock::now();
	auto tp_now_sec = std::chrono::floor<std::chrono::seconds>(tp_now);
	auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(
		tp_now - tp_now_sec
	);
	auto ts_sec = tp_now_sec.time_since_epoch().count();
	auto ts_usec = duration_us.count();

	const char *buf = reinterpret_cast<const char*>(pmt::blob_data(pmt::cdr(pdu)));
	std::size_t len = pmt::blob_length(pmt::cdr(pdu));
	std::size_t offset = 0;

	switch(d_link) {

	case WIFI: {

		// if crc is included ignore last 4 bytes
		pmt::pmt_t dict = pmt::car(pdu);
		pmt::pmt_t crc_inc = pmt::dict_ref(dict, pmt::mp("crc_included"), pmt::PMT_NIL);
		if(pmt::is_bool(crc_inc) && pmt::is_true(crc_inc)) {
			len -= 4;
		}

		// Extract CSI data from PMT dictionary
		std::size_t csi_data_size = 0;
		std::vector<uint8_t> csi_bytes;
		
		pmt::pmt_t csi_pmt = pmt::dict_ref(dict, pmt::mp("csi"), pmt::PMT_NIL);
		
		if(d_debug) {
			std::cout << "WIRESHARK: CSI PMT is_null: " << pmt::is_null(csi_pmt) << std::endl;
			std::cout << "WIRESHARK: CSI PMT is_vector: " << pmt::is_vector(csi_pmt) << std::endl;
			std::cout << "WIRESHARK: CSI PMT is_c32vector: " << pmt::is_c32vector(csi_pmt) << std::endl;
			std::cout << "WIRESHARK: CSI PMT is_c64vector: " << pmt::is_c64vector(csi_pmt) << std::endl;
		}
		
		if(!pmt::is_null(csi_pmt)) {
			size_t csi_len = 0;
			
			// Handle different PMT vector types for CSI data
			if(pmt::is_c32vector(csi_pmt)) {
				// CSI stored as 32-bit complex vector
				csi_len = pmt::length(csi_pmt);
				const std::vector<std::complex<float>>& csi_data = pmt::c32vector_elements(csi_pmt);
				
				// Reserve space for CSI data: each complex number = 2 floats (8 bytes)
				csi_bytes.reserve(csi_len * 8);
				
				for(size_t i = 0; i < csi_len; i++) {
					float real_part = csi_data[i].real();
					float imag_part = csi_data[i].imag();
					
					// Add real part bytes (little-endian)
					uint8_t* real_bytes = reinterpret_cast<uint8_t*>(&real_part);
					csi_bytes.insert(csi_bytes.end(), real_bytes, real_bytes + 4);
					
					// Add imaginary part bytes (little-endian)
					uint8_t* imag_bytes = reinterpret_cast<uint8_t*>(&imag_part);
					csi_bytes.insert(csi_bytes.end(), imag_bytes, imag_bytes + 4);
				}
				
			} else if(pmt::is_c64vector(csi_pmt)) {
				// CSI stored as 64-bit complex vector
				csi_len = pmt::length(csi_pmt);
				const std::vector<std::complex<double>>& csi_data = pmt::c64vector_elements(csi_pmt);
				
				// Reserve space for CSI data: each complex number = 2 floats (8 bytes)
				csi_bytes.reserve(csi_len * 8);
				
				for(size_t i = 0; i < csi_len; i++) {
					float real_part = static_cast<float>(csi_data[i].real());
					float imag_part = static_cast<float>(csi_data[i].imag());
					
					// Add real part bytes (little-endian)
					uint8_t* real_bytes = reinterpret_cast<uint8_t*>(&real_part);
					csi_bytes.insert(csi_bytes.end(), real_bytes, real_bytes + 4);
					
					// Add imaginary part bytes (little-endian)
					uint8_t* imag_bytes = reinterpret_cast<uint8_t*>(&imag_part);
					csi_bytes.insert(csi_bytes.end(), imag_bytes, imag_bytes + 4);
				}
				
			} else if(pmt::is_vector(csi_pmt)) {
				// CSI stored as regular vector of complex numbers
				csi_len = pmt::length(csi_pmt);
				
				// Reserve space for CSI data: each complex number = 2 floats (8 bytes)
				csi_bytes.reserve(csi_len * 8);
				
				for(size_t i = 0; i < csi_len; i++) {
					pmt::pmt_t csi_element = pmt::vector_ref(csi_pmt, i);
					if(pmt::is_complex(csi_element)) {
						std::complex<double> csi_val = pmt::to_complex(csi_element);
						
						// Convert real and imaginary parts to float32 and add to byte vector
						float real_part = static_cast<float>(csi_val.real());
						float imag_part = static_cast<float>(csi_val.imag());
						
						// Add real part bytes (little-endian)
						uint8_t* real_bytes = reinterpret_cast<uint8_t*>(&real_part);
						csi_bytes.insert(csi_bytes.end(), real_bytes, real_bytes + 4);
						
						// Add imaginary part bytes (little-endian)
						uint8_t* imag_bytes = reinterpret_cast<uint8_t*>(&imag_part);
						csi_bytes.insert(csi_bytes.end(), imag_bytes, imag_bytes + 4);
					}
				}
			}
			
			csi_data_size = csi_bytes.size();
			
			if(d_debug) {
				std::cout << "WIRESHARK: CSI length: " << csi_len << std::endl;
				std::cout << "WIRESHARK: CSI data size in bytes: " << csi_data_size << std::endl;
			}
		}

		// Calculate total size: original payload + marker (4 bytes) + CSI data
		std::size_t additional_data_size = 4 + 8+8 +csi_data_size; // 4 bytes marker + CSI data
		std::size_t total_payload_size = len + additional_data_size;

		// pcap header - allocate memory for original payload + additional data
		d_msg = reinterpret_cast<char*>(std::malloc(
				total_payload_size + sizeof(radiotap_hdr) + sizeof(pcap_hdr)));

		pcap_hdr *hdr = reinterpret_cast<pcap_hdr*>(d_msg);
		hdr->ts_sec   = ts_sec;
		hdr->ts_usec  = ts_usec;
		hdr->incl_len = total_payload_size + sizeof(radiotap_hdr);
		hdr->orig_len = total_payload_size + sizeof(radiotap_hdr);
		offset += sizeof(struct pcap_hdr);

		// check if rate is attached
		uint8_t rate = 12;
		pmt::pmt_t encoding = pmt::dict_ref(dict, pmt::mp("encoding"), pmt::PMT_NIL);
		if(pmt::is_uint64(encoding)) {
			rate = encoding_to_rate(pmt::to_uint64(encoding));
		}

		int snr = 42;
		if(pmt::dict_has_key(dict, pmt::mp("snr"))) {
			pmt::pmt_t s = pmt::dict_ref(dict, pmt::mp("snr"), pmt::PMT_NIL);
			if(pmt::is_number(s)) {
				snr = std::round(pmt::to_double(s));
			}
		}

		uint8_t signal = 0;
		uint8_t noise = 0;

		if(snr >= 0) {
			signal = snr;
			noise = 0;
		} else {
			signal = 0;
			noise = -1 * snr;
		}

		// radiotap header
		radiotap_hdr *rhdr = reinterpret_cast<radiotap_hdr*>(d_msg + offset);
		rhdr->version     = 0;
		rhdr->hdr_length  = sizeof(radiotap_hdr);
		rhdr->bitmap      = 0x0000086e;
		rhdr->flags       = 0;
		rhdr->rate        = rate;
		rhdr->channel     = 178;
		rhdr->signal      = signal;
		rhdr->noise       = noise;
		rhdr->antenna     = 1;
		offset += sizeof(struct radiotap_hdr);

		// Copy original 802.11 payload
		memcpy(d_msg + offset, buf, len);
		offset += len;

		// Append marker bytes: 0x00 0x01 0x02 0x03
		uint8_t marker_bytes[4] = {0x00, 0x01, 0x02, 0x03};
		memcpy(d_msg + offset, marker_bytes, 4);
		offset += 4;

		// 2. Insert "signal" as double (8 bytes)
		double signal_val = 0.0;
		if (pmt::dict_has_key(dict, pmt::mp("signal"))) {
			pmt::pmt_t val = pmt::dict_ref(dict, pmt::mp("signal"), pmt::PMT_NIL);
			if (pmt::is_number(val)) {
				signal_val = pmt::to_double(val);
			}
		}
		// Copy aaa_val as 8 bytes (double) to buffer
		memcpy(d_msg + offset, &signal_val, sizeof(double));
		offset += sizeof(double); // Advance offset by 8 bytes

		// 3. Insert "noise" as double (8 bytes)
		double noise_val = 0.0;
		if (pmt::dict_has_key(dict, pmt::mp("noise"))) {
			pmt::pmt_t val = pmt::dict_ref(dict, pmt::mp("noise"), pmt::PMT_NIL);
			if (pmt::is_number(val)) {
				noise_val = pmt::to_double(val);
			}
		}
		
		memcpy(d_msg + offset, &noise_val, sizeof(double));
		offset += sizeof(double); // Advance offset by 8 bytes

		// Append CSI data
		if(csi_data_size > 0) {
			memcpy(d_msg + offset, csi_bytes.data(), csi_data_size);
			offset += csi_data_size;
		}

		d_msg_len = offset;
		
		if(d_debug) {
			std::cout << "WIRESHARK: Added " << additional_data_size 
					  << " bytes (4 marker + " << csi_data_size << " CSI bytes)" << std::endl;
		}

		return; // Important: return here to skip the generic memcpy below
	}


	case ZIGBEE: {

		d_msg = reinterpret_cast<char*>(std::malloc(
				len + sizeof(pcap_hdr)));

		pcap_hdr *hdr = reinterpret_cast<pcap_hdr*>(d_msg);
		hdr->ts_sec   = ts_sec;
		hdr->ts_usec  = ts_usec;
		hdr->incl_len = len;
		hdr->orig_len = len;
		offset += sizeof(pcap_hdr);
		break;
	}

	
	case ZIGBEE_TAP:{

		const size_t max_extra_size = sizeof(tap_hdr) + sizeof(tap_tlv_fcs) + sizeof(tap_tlv_channel) + sizeof(tap_tlv_lqi);
		size_t extra_size = sizeof(tap_hdr) + sizeof(tap_tlv_fcs);
		d_msg = reinterpret_cast<char*>(std::malloc(len + sizeof(pcap_hdr) + max_extra_size));


		pcap_hdr *hdr = reinterpret_cast<pcap_hdr*>(d_msg);
		hdr->ts_sec   = ts_sec;
		hdr->ts_usec  = ts_usec;
		// hdr->incl_len is set at the end of the scope
		// hdr->orig_len is set at the end of the scope
		offset += sizeof(pcap_hdr);

		tap_hdr *tap = reinterpret_cast<tap_hdr*>(d_msg + offset);
		tap->version = 0;
		tap->reserved = 0;
		// tap->length is set at the end of the scope
		offset += sizeof(tap_hdr);

		tap_tlv_fcs *fcs = reinterpret_cast<tap_tlv_fcs*>(d_msg + offset);
		fcs->type = 0; // FCS_TYPE
		fcs->length = 1;
		fcs->fcs_type = 1; // 16 bit crc
		for (int i = 0; i < 3; i++) {
			fcs->padding[i] = 0;
		}
		offset += sizeof(tap_tlv_fcs);

		pmt::pmt_t dict = pmt::car(pdu);
		if(pmt::dict_has_key(dict, pmt::mp("channel"))) {
			pmt::pmt_t s = pmt::dict_ref(dict, pmt::mp("channel"), pmt::PMT_NIL);
			if(pmt::is_integer(s)) {
				tap_tlv_channel *chan = reinterpret_cast<tap_tlv_channel*>(d_msg + offset);
				chan->type = 3; // CHANNEL_ASSIGNMENT
				chan->length = 3;
				chan->channel_number = (uint16_t)pmt::to_long(s);
				chan->channel_page = 0;
				chan->padding = 0;
				offset += sizeof(tap_tlv_channel);
				extra_size += sizeof(tap_tlv_channel);
			}
		}

		if(pmt::dict_has_key(dict, pmt::mp("lqi"))) {
			pmt::pmt_t s = pmt::dict_ref(dict, pmt::mp("lqi"), pmt::PMT_NIL);
			if(pmt::is_integer(s)) {
				tap_tlv_lqi *lqi = reinterpret_cast<tap_tlv_lqi*>(d_msg + offset);
				lqi->type = 10; // LQI
				lqi->length = 1;
				lqi->lqi = (uint8_t)pmt::to_long(s);
				for (int i = 0; i < 3; i++) {
					lqi->padding[i] = 0;
				}
				offset += sizeof(tap_tlv_lqi);
				extra_size += sizeof(tap_tlv_lqi);
			}
		}

		tap->length = extra_size;
		hdr->incl_len = len + extra_size;
		hdr->orig_len = len + extra_size;
		break;
	}

	}

	memcpy(d_msg + offset, buf, len);
	d_msg_len = offset + len;
}

uint8_t
wireshark_connector_impl::encoding_to_rate(uint64_t encoding) {

	// rates in radiotab rate field
	// are in 0.5 Mbit/s steps
	switch(encoding) {
	case 0:
		return  6 * 2;
	case 1:
		return  9 * 2;
	case 2:
		return 12 * 2;
	case 3:
		return 18 * 2;
	case 4:
		return 24 * 2;
	case 5:
		return 36 * 2;
	case 6:
		return 48 * 2;
	case 7:
		return 54 * 2;
	}

	throw std::invalid_argument("wrong encoding");
	return 0;
}

int
wireshark_connector_impl::general_work(int noutput, gr_vector_int& ninput_items,
                gr_vector_const_void_star& input_items,
		gr_vector_void_star& output_items ) {

	gr_complex *out = (gr_complex*)output_items[0];

	if(!d_msg_len) {
		pmt::pmt_t msg(delete_head_nowait(pmt::mp("in")));

		if(!msg) {
			return 0;
		}

		if(pmt::is_eof_object(msg)) {
			dout << "WIRESHARK: exiting" << std::endl;
			return -1;
		} else if(pmt::is_pair(msg)) {
			dout << "WIRESHARK: received new message" << std::endl;
			dout << "message length " << pmt::blob_length(pmt::cdr(msg)) << std::endl;
			handle_pdu(msg);
		} else {
			dout << "WIRESHARK: ignoring message" << std::endl;
			return 0;
		}
	}

	int to_copy = std::min((d_msg_len - d_msg_offset), noutput);
	memcpy(out, d_msg + d_msg_offset, to_copy);

	dout << "WIRESHARK: d_msg_offset: " <<  d_msg_offset <<
		"   to_copy: " << to_copy <<
		"   d_msg_len " << d_msg_len << std::endl;

	d_msg_offset += to_copy;

	if(d_msg_offset == d_msg_len) {
		d_msg_offset = 0;
		d_msg_len = 0;
		std::free(d_msg);
	}

	dout << "WIRESHARK: output size: " <<  noutput <<
		"   produced items: " << to_copy << std::endl;
	return to_copy;
}

wireshark_connector::sptr
wireshark_connector::make(LinkType type, bool debug) {
	return gnuradio::get_initial_sptr(new wireshark_connector_impl(type, debug));
}
