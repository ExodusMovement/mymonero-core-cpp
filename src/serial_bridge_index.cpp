//
//  serial_bridge_index.cpp
//  Copyright (c) 2014-2019, MyMonero.com
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without modification, are
//  permitted provided that the following conditions are met:
//
//  1. Redistributions of source code must retain the above copyright notice, this list of
//	conditions and the following disclaimer.
//
//  2. Redistributions in binary form must reproduce the above copyright notice, this list
//	of conditions and the following disclaimer in the documentation and/or other
//	materials provided with the distribution.
//
//  3. Neither the name of the copyright holder nor the names of its contributors may be
//	used to endorse or promote products derived from this software without specific
//	prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
//  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
//  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
//  THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
//  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
//  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
//  THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//
//
#include "serial_bridge_index.hpp"
//
#include <algorithm>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/foreach.hpp>
//
#include "monero_fork_rules.hpp"
#include "monero_transfer_utils.hpp"
#include "monero_address_utils.hpp" // TODO: split this/these out into a different namespaces or file so this file can scale (leave file for shared utils)
#include "monero_paymentID_utils.hpp"
#include "monero_wallet_utils.hpp"
#include "monero_key_image_utils.hpp"
#include "wallet_errors.h"
#include "string_tools.h"
#include "ringct/rctSigs.h"
#include "common/threadpool.h"
#include "storages/portable_storage_template_helper.h"
//
#include "extend_helpers.hpp"
#include "serial_bridge_utils.hpp"

#ifdef __linux__
#ifndef __ANDROID_API__
#include <bsd/stdlib.h>
#endif
#endif

using namespace std;
using namespace boost;
using namespace cryptonote;
using namespace extend_helpers;
using namespace monero_transfer_utils;
using namespace monero_fork_rules;
//
using namespace serial_bridge;
using namespace serial_bridge_utils;

const char *serial_bridge::create_blocks_request(int height, size_t *length) {
	crypto::hash genesis;
	epee::string_tools::hex_to_pod("418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3", genesis);

	cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::request req;
	req.block_ids.push_back(genesis);
	req.start_height = height;
	req.prune = true;
	req.no_miner_tx = false;

	std::string m_body;
	epee::serialization::store_t_to_binary(req, m_body);

	*length = m_body.length();
	char *arr = (char *)malloc(m_body.length());
	std::copy(m_body.begin(), m_body.end(), arr);

	return (const char *)arr;
}

const char* serial_bridge::decompress(const char *buffer, size_t length) {
    if (buffer == nullptr || length == 0) {
        throw std::invalid_argument("Invalid input data");
    }

    int ret;
    z_stream strm;
    static const size_t BUFFER_SIZE = 32768;
    unsigned char outBuffer[BUFFER_SIZE];
    std::vector<char> decompressedData;  // Use vector<char> for dynamic storage

    // Initialize the decompression stream
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.total_out = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit2(&strm, (16 + MAX_WBITS));  // MAX_WBITS + 16 for gzip decoding
    if (ret != Z_OK) {
        throw std::runtime_error("inflateInit failed while decompressing.");
    }

    // Set the input data
    strm.avail_in = length;
    strm.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(buffer));

    // Decompress until deflate stream ends or end of file
    do {
        strm.avail_out = sizeof(outBuffer);
        strm.next_out = outBuffer;
        ret = inflate(&strm, Z_NO_FLUSH);
        switch (ret) {
            case Z_NEED_DICT:
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                inflateEnd(&strm);
                throw std::runtime_error("Decompression error");
        }

        decompressedData.insert(decompressedData.end(), outBuffer, outBuffer + sizeof(outBuffer) - strm.avail_out);
    } while (ret == Z_OK);

    // Clean up the zlib stream
    inflateEnd(&strm);
    if (ret != Z_STREAM_END) {
        throw std::runtime_error("Incomplete decompression: more data was expected");
    }

    // Allocate memory for the return value
    char* result = new char[decompressedData.size() + 1];
    std::memcpy(result, decompressedData.data(), decompressedData.size());
    result[decompressedData.size()] = '\0';  // Null-terminate the string

    return result;
}

std::map<std::string, WalletAccountParams> serial_bridge::get_wallet_accounts_params(boost::property_tree::ptree tree) {
    std::map<std::string, WalletAccountParams> wallet_accounts_params;
    for (const auto &params_desc : tree) {
        WalletAccountParams wallet_account_params;

        if (!epee::string_tools::hex_to_pod(params_desc.second.get<string>("sec_viewKey_string"), wallet_account_params.account_keys.m_view_secret_key)) {
            continue;
        }

        if (!epee::string_tools::hex_to_pod(params_desc.second.get<string>("pub_spendKey_string"), wallet_account_params.account_keys.m_account_address.m_spend_public_key)) {
            continue;
        }

        wallet_account_params.account_keys.m_spend_secret_key = crypto::null_skey;
        auto secSpendKeyString = params_desc.second.get_optional<string>("sec_spendKey_string");
        if (secSpendKeyString && !epee::string_tools::hex_to_pod(*secSpendKeyString, wallet_account_params.account_keys.m_spend_secret_key)) {
            continue;
        }

        auto send_txs_child = params_desc.second.get_child_optional("send_txs");
        if (send_txs_child) {
            wallet_account_params.has_send_txs = true;

            for (const auto &send_tx_desc : *send_txs_child) {
                assert(send_tx_desc.first.empty());
                wallet_account_params.send_txs.insert(std::pair<std::string, bool>(send_tx_desc.second.get_value<std::string>(), true));
            }
        }

        auto key_images_child = params_desc.second.get_child_optional("key_images");
        if (key_images_child) {
            for (const auto &image_desc : *key_images_child) {
                assert(image_desc.first.empty());
                wallet_account_params.gki.insert(std::pair<std::string, bool>(image_desc.second.get_value<std::string>(), true));
            }
        }

        uint32_t subaddresses_count = params_desc.second.get<uint32_t>("subaddresses");

        cryptonote::subaddress_index index = {0, 0};
        expand_subaddresses(wallet_account_params.account_keys, wallet_account_params.subaddresses, index, subaddresses_count);

        wallet_accounts_params.insert(std::make_pair(params_desc.first, wallet_account_params));
    }

    return wallet_accounts_params;
}

NativeResponse serial_bridge::extract_data_from_blocks_response(const char *buffer, size_t length, const string &args_string) {
	NativeResponse native_resp;

	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		native_resp.error = "Invalid JSON";
		return native_resp;
	}

	std::string storage_path = json_root.get<string>("storage_path");
	uint8_t storage_rate = json_root.get<uint8_t>("storage_percent");
	uint64_t latest = json_root.get<uint64_t>("latest");
	uint64_t oldest = json_root.get<uint64_t>("oldest");
	uint64_t size = json_root.get<uint64_t>("size");

	std::map<std::string, WalletAccountParams> wallet_accounts_params = serial_bridge::get_wallet_accounts_params(json_root.get_child("params_by_wallet_account"));
	for (const auto &pair : wallet_accounts_params) {
		native_resp.results_by_wallet_account.insert(std::make_pair(pair.first, ExtractTransactionsResult{}));
	}

	std::string m_body(buffer, length);

	cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response resp;
	if (!epee::serialization::load_t_from_binary(resp, m_body)) {
		native_resp.error = "Network request failed";
		return native_resp;
	}

	auto blocks = resp.blocks;

	for (size_t i = 0; i < resp.blocks.size(); i++) {
		auto block_entry = resp.blocks[i];

		PrunedBlock pruned_block;
		cryptonote::block b;

		crypto::hash block_hash;
		if (!parse_and_validate_block_from_blob(block_entry.block, b, block_hash)) {
			continue;
		}

		auto gen_tx = b.miner_tx.vin[0];
		if (gen_tx.type() != typeid(cryptonote::txin_gen)) {
			continue;
		}

		uint64_t height = boost::get<cryptonote::txin_gen>(gen_tx).height;
		native_resp.end_height = std::max(native_resp.end_height, height);

		pruned_block.block_height = height;
		pruned_block.timestamp = b.timestamp;
		for (size_t j = 0; j < block_entry.txs.size(); j++) {
			auto tx_entry = block_entry.txs[j];

			cryptonote::transaction tx;

			auto tx_parsed = cryptonote::parse_and_validate_tx_from_blob(tx_entry.blob, tx) || cryptonote::parse_and_validate_tx_base_from_blob(tx_entry.blob, tx);
            if (!tx_parsed)
				continue;

			std::vector<cryptonote::tx_extra_field> fields;
			auto extra_parsed = cryptonote::parse_tx_extra(tx.extra, fields);
			if (!extra_parsed)
				continue;

			BridgeTransaction bridge_tx;
			bridge_tx.id = epee::string_tools::pod_to_hex(b.tx_hashes[j]);
			bridge_tx.version = tx.version;
			bridge_tx.timestamp = b.timestamp;
			bridge_tx.block_height = height;
			bridge_tx.rv = tx.rct_signatures;
			bridge_tx.pub = get_extra_pub_key(fields);
			bridge_tx.additional_pubs = get_extra_additional_tx_pub_keys(fields);
			bridge_tx.fee_amount = get_fee(tx, bridge_tx);
			bridge_tx.outputs = get_outputs(tx);

			auto nonce = get_extra_nonce(fields);
			if (!cryptonote::get_encrypted_payment_id_from_tx_extra_nonce(nonce, bridge_tx.payment_id8))
			{
				cryptonote::get_payment_id_from_tx_extra_nonce(nonce, bridge_tx.payment_id);
			}

			if (bridge_tx.version == 2)
			{
				for (size_t k = 0; k < bridge_tx.outputs.size(); k++)
				{
					auto &output = bridge_tx.outputs[k];

					Mixin mixin;
					mixin.global_index = resp.output_indices[i].indices[j + 1].indices[output.index];
					mixin.public_key = output.pub;
					mixin.rct = build_rct(bridge_tx.rv, output.index);

					pruned_block.mixins.push_back(mixin);
				}
			}

			for (auto &pair : wallet_accounts_params)
			{
				auto bridge_tx_copy = bridge_tx;

				auto &wallet_account_params = pair.second;
				bridge_tx_copy.inputs = wallet_account_params.has_send_txs ? get_inputs_with_send_txs(tx, bridge_tx_copy, wallet_account_params.send_txs) : get_inputs(tx, bridge_tx_copy, wallet_account_params.gki);

				auto tx_utxos = extract_utxos_from_tx(bridge_tx_copy, wallet_account_params.account_keys, wallet_account_params.subaddresses);

				for (size_t k = 0; k < tx_utxos.size(); k++)
				{
					auto &utxo = tx_utxos[k];
					utxo.global_index = resp.output_indices[i].indices[j + 1].indices[utxo.vout];

					if (!wallet_account_params.has_send_txs)
					{
						wallet_account_params.gki.insert(std::pair<std::string, bool>(utxo.key_image, true));
					}
				}

				bridge_tx_copy.utxos = tx_utxos;

				if (bridge_tx_copy.utxos.size() != 0 || bridge_tx_copy.inputs.size() != 0)
				{
					auto &result = native_resp.results_by_wallet_account[pair.first];
					result.txs.push_back(bridge_tx_copy);
				}
			}
		}

#ifndef EMSCRIPTEN
		if (pruned_block.block_height >= oldest && pruned_block.block_height <= latest)
			continue;
		if (size <= 100 || arc4random_uniform(100) < storage_rate)
		{
			std::ofstream f;
			f.open(storage_path + std::to_string(pruned_block.block_height) + ".json");
			f << ret_json_from_root(pruned_block_to_json(pruned_block));

			if (f.good())
			{
				latest = std::max(latest, pruned_block.block_height);
				oldest = std::min(oldest, pruned_block.block_height);
				size += 1;
			}

			f.close();
		}
#endif
	}

	for (const auto& pair : wallet_accounts_params) {
		auto &result = native_resp.results_by_wallet_account[pair.first];

		result.subaddresses = pair.second.subaddresses.size();
	}

	native_resp.current_height = resp.current_height;
	native_resp.latest = latest;
	native_resp.oldest = oldest;
	native_resp.size = size;

	return native_resp;
}

NativeResponse serial_bridge::extract_data_from_clarity_blocks_response(const char *buffer, size_t length, const string &args_string) {
	NativeResponse native_resp;

	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		native_resp.error = "Invalid JSON";
		return native_resp;
	}

	std::string storage_path = json_root.get<string>("storage_path");
	uint8_t storage_rate = json_root.get<uint8_t>("storage_percent");
	uint64_t latest = json_root.get<uint64_t>("latest");
	uint64_t oldest = json_root.get<uint64_t>("oldest");
	uint64_t size = json_root.get<uint64_t>("size");

	std::map<std::string, WalletAccountParams> wallet_accounts_params = serial_bridge::get_wallet_accounts_params(json_root.get_child("params_by_wallet_account"));
	for (const auto &pair : wallet_accounts_params) {
		native_resp.results_by_wallet_account.insert(std::make_pair(pair.first, ExtractTransactionsResult{}));
	}

    boost::property_tree::ptree blocks_json_root;
    const char* decompressed_blocks = nullptr;
    try {
        decompressed_blocks = serial_bridge::decompress(buffer, length);
        if (!parsed_json_root(decompressed_blocks, blocks_json_root)) {
            native_resp.error = "Invalid blocks JSON";
            delete[] decompressed_blocks; // Clean up the allocated memory
            return native_resp;
        }
    } catch (const std::exception& e) {
        native_resp.error = std::string("Error processing blocks data from clarity: ") + e.what();

        // Clean up the allocated memory
        if (decompressed_blocks) {
            delete[] decompressed_blocks;
        }
        return native_resp;
    }

    for (auto &block_json_root : blocks_json_root) {
        boost::property_tree::ptree& block_entry = block_json_root.second;

        uint64_t height = block_entry.get<uint64_t>("id");
        auto& block = block_entry.get_child("block");

        uint64_t timestamp = block.get<uint64_t>("block_header.timestamp");

        std::vector<std::string> tx_hashes;
        for (const auto& hash : block.get_child("transaction_hashes")) {
            tx_hashes.push_back(hash.second.data());
        }

        std::vector<std::string> txs;
        for (const auto& tx : block_entry.get_child("txs")) {
            std::string tx_blob;
            decode_base64(tx.second.data(), tx_blob);
            txs.push_back(tx_blob);
        }

        BlockOutputIndices output_indices;
        for (auto& output_index_array : block_entry.get_child("outputIndices")) {
            TxOutputIndices indices;
            for (auto& index : output_index_array.second) {
                indices.push_back(index.second.get_value<uint64_t>());
            }
            output_indices.push_back(indices);
        }

        native_resp.end_height = std::max(native_resp.end_height, height);

        PrunedBlock pruned_block;
        pruned_block.block_height = height;
		pruned_block.timestamp = timestamp;
        for (size_t j = 0; j < txs.size(); j++) {
            std::string tx_blob = txs[j];
			cryptonote::transaction tx;

			auto tx_parsed = cryptonote::parse_and_validate_tx_from_blob(tx_blob, tx) || cryptonote::parse_and_validate_tx_base_from_blob(tx_blob, tx);
            if (!tx_parsed)
				continue;

			std::vector<cryptonote::tx_extra_field> fields;
			auto extra_parsed = cryptonote::parse_tx_extra(tx.extra, fields);
			if (!extra_parsed)
				continue;

			BridgeTransaction bridge_tx;
			bridge_tx.id = tx_hashes[j];
			bridge_tx.version = tx.version;
			bridge_tx.timestamp = timestamp;
			bridge_tx.block_height = height;
			bridge_tx.rv = tx.rct_signatures;
			bridge_tx.pub = get_extra_pub_key(fields);
			bridge_tx.additional_pubs = get_extra_additional_tx_pub_keys(fields);
			bridge_tx.fee_amount = get_fee(tx, bridge_tx);
			bridge_tx.outputs = get_outputs(tx);

			auto nonce = get_extra_nonce(fields);
			if (!cryptonote::get_encrypted_payment_id_from_tx_extra_nonce(nonce, bridge_tx.payment_id8))
			{
				cryptonote::get_payment_id_from_tx_extra_nonce(nonce, bridge_tx.payment_id);
			}

			if (bridge_tx.version == 2)
			{
				for (size_t k = 0; k < bridge_tx.outputs.size(); k++)
				{
					auto &output = bridge_tx.outputs[k];

					Mixin mixin;
					mixin.global_index = output_indices[j + 1][output.index];
					mixin.public_key = output.pub;
					mixin.rct = build_rct(bridge_tx.rv, output.index);

					pruned_block.mixins.push_back(mixin);
				}
			}

			for (auto &pair : wallet_accounts_params)
			{
				auto bridge_tx_copy = bridge_tx;

				auto &wallet_account_params = pair.second;
				bridge_tx_copy.inputs = wallet_account_params.has_send_txs ? get_inputs_with_send_txs(tx, bridge_tx_copy, wallet_account_params.send_txs) : get_inputs(tx, bridge_tx_copy, wallet_account_params.gki);

				auto tx_utxos = extract_utxos_from_tx(bridge_tx_copy, wallet_account_params.account_keys, wallet_account_params.subaddresses);

				for (size_t k = 0; k < tx_utxos.size(); k++)
				{
					auto &utxo = tx_utxos[k];
					utxo.global_index = output_indices[j + 1][utxo.vout];

					if (!wallet_account_params.has_send_txs)
					{
						wallet_account_params.gki.insert(std::pair<std::string, bool>(utxo.key_image, true));
					}
				}

				bridge_tx_copy.utxos = tx_utxos;

				if (bridge_tx_copy.utxos.size() != 0 || bridge_tx_copy.inputs.size() != 0)
				{
					auto &result = native_resp.results_by_wallet_account[pair.first];
					result.txs.push_back(bridge_tx_copy);
				}
			}
		}

#ifndef EMSCRIPTEN
		if (pruned_block.block_height >= oldest && pruned_block.block_height <= latest)
			continue;
		if (size <= 100 || arc4random_uniform(100) < storage_rate)
		{
			std::ofstream f;
			f.open(storage_path + std::to_string(pruned_block.block_height) + ".json");
			f << ret_json_from_root(pruned_block_to_json(pruned_block));

			if (f.good())
			{
				latest = std::max(latest, pruned_block.block_height);
				oldest = std::min(oldest, pruned_block.block_height);
				size += 1;
			}

			f.close();
		}
#endif
	}

	for (const auto& pair : wallet_accounts_params) {
		auto &result = native_resp.results_by_wallet_account[pair.first];

		result.subaddresses = pair.second.subaddresses.size();
	}

	native_resp.current_height = 0; // clarity does not return it in the blocks API, we need to get it from monitor
	native_resp.latest = latest;
	native_resp.oldest = oldest;
	native_resp.size = size;

	return native_resp;
}

std::string serial_bridge::extract_data_from_blocks_response_str(const char *buffer, size_t length, const string &args_string) {
	auto resp = serial_bridge::extract_data_from_blocks_response(buffer, length, args_string);
    return serial_bridge::native_response_to_json_str(resp);
}

std::string serial_bridge::extract_data_from_clarity_blocks_response_str(const char *buffer, size_t length, const string &args_string) {
    auto resp = serial_bridge::extract_data_from_clarity_blocks_response(buffer, length, args_string);
    return serial_bridge::native_response_to_json_str(resp);
}

std::string serial_bridge::native_response_to_json_str(const NativeResponse &resp) {
    boost::property_tree::ptree root;

    if (!resp.error.empty()) {
        root.put(ret_json_key__any__err_msg(), resp.error);
        return ret_json_from_root(root);
    }

    root.put("current_height", resp.current_height);
    root.put("end_height", resp.end_height);
    root.put("latest", resp.latest);
    root.put("oldest", resp.oldest);
    root.put("size", resp.size);

    boost::property_tree::ptree results_tree;
    for (const auto &pair : resp.results_by_wallet_account) {
        boost::property_tree::ptree txs_tree;
        for (const auto &tx : pair.second.txs) {
            boost::property_tree::ptree tx_tree;

            tx_tree.put("id", tx.id);
            tx_tree.put("timestamp", tx.timestamp);
            tx_tree.put("height", tx.block_height);
            tx_tree.put("pub", epee::string_tools::pod_to_hex(tx.pub));

            boost::property_tree::ptree additional_pubs_tree;
            for (const auto& pub : tx.additional_pubs) {
                boost::property_tree::ptree value;
                value.put("", epee::string_tools::pod_to_hex(pub));

                additional_pubs_tree.push_back(std::make_pair("", value));
            }
            tx_tree.add_child("additional_pubs", additional_pubs_tree);

            tx_tree.put("fee", tx.fee_amount);

            if (tx.payment_id8 != crypto::null_hash8) {
                tx_tree.put("epid", epee::string_tools::pod_to_hex(tx.payment_id8));
            }
            else if (tx.payment_id != crypto::null_hash) {
                tx_tree.put("pid", epee::string_tools::pod_to_hex(tx.payment_id));
            }

            tx_tree.add_child("inputs", inputs_to_json(tx.inputs));
            tx_tree.add_child("utxos", utxos_to_json(tx.utxos, true));

            txs_tree.push_back(std::make_pair("", tx_tree));
        }

        boost::property_tree::ptree wallet_tree;
        wallet_tree.add_child("txs", txs_tree);
        wallet_tree.put("subaddresses", pair.second.subaddresses);

        results_tree.add_child(pair.first, wallet_tree);
    }

    root.add_child("results", results_tree);

    return ret_json_from_root(root);
}

std::string serial_bridge::get_transaction_pool_hashes_str(const char *buffer, size_t length) {
	std::string m_body(buffer, length);

	cryptonote::COMMAND_RPC_GET_TRANSACTION_POOL_HASHES_BIN::response resp;
	if (!epee::serialization::load_t_from_json(resp, m_body)) {
		return error_ret_json_from_message("Network request failed");
	}

	if (resp.status != "OK") {
		return error_ret_json_from_message("Network request failed");
	}

	boost::property_tree::ptree root;

	boost::property_tree::ptree tx_hashes_tree;
	for (int i = 0; i < resp.tx_hashes.size(); i++) {
		boost::property_tree::ptree tx_hash_tree;
		tx_hash_tree.put("", epee::string_tools::pod_to_hex(resp.tx_hashes[i]));

		tx_hashes_tree.push_back(std::make_pair("", tx_hash_tree));
	}
	root.add_child("tx_hashes", tx_hashes_tree);

	return ret_json_from_root(root);
}

crypto::public_key serial_bridge::get_extra_pub_key(const std::vector<cryptonote::tx_extra_field> &fields) {
	for (size_t n = 0; n < fields.size(); ++n) {
		if (typeid(cryptonote::tx_extra_pub_key) == fields[n].type())
		{
			return boost::get<cryptonote::tx_extra_pub_key>(fields[n]).pub_key;
		}
	}

	return crypto::public_key{};
}

std::vector<crypto::public_key> serial_bridge::get_extra_additional_tx_pub_keys(const std::vector<cryptonote::tx_extra_field> &fields)
{
	for (size_t n = 0; n < fields.size(); ++n) {
		if (typeid(cryptonote::tx_extra_additional_pub_keys) == fields[n].type())
		{
			return boost::get<cryptonote::tx_extra_additional_pub_keys>(fields[n]).data;
		}
	}

	return {};
}

std::string serial_bridge::get_extra_nonce(const std::vector<cryptonote::tx_extra_field> &fields)
{
	for (size_t n = 0; n < fields.size(); ++n) {
		if (typeid(cryptonote::tx_extra_nonce) == fields[n].type())
		{
			return boost::get<cryptonote::tx_extra_nonce>(fields[n]).nonce;
		}
	}

	return "";
}

std::vector<crypto::key_image> serial_bridge::get_inputs(const cryptonote::transaction &tx, const BridgeTransaction &bridge_tx, std::map<std::string, bool> &gki)
{
	std::vector<crypto::key_image> inputs;

	for (size_t i = 0; i < tx.vin.size(); i++) {
		auto &tx_in = tx.vin[i];
		if (tx_in.type() != typeid(cryptonote::txin_to_key))
			continue;

		auto image = boost::get<cryptonote::txin_to_key>(tx_in).k_image;

		auto it = gki.find(epee::string_tools::pod_to_hex(image));
		if (it == gki.end())
			continue;

		gki.erase(it);

		inputs.push_back(image);
	}

	return inputs;
}

std::vector<crypto::key_image> serial_bridge::get_inputs_with_send_txs(const cryptonote::transaction &tx, const BridgeTransaction &bridge_tx, std::map<std::string, bool> &send_txs)
{
	std::vector<crypto::key_image> inputs;

	auto it = send_txs.find(bridge_tx.id);
	if (it == send_txs.end())
		return inputs;

	for (size_t i = 0; i < tx.vin.size(); i++) {
		auto &tx_in = tx.vin[i];
		if (tx_in.type() != typeid(cryptonote::txin_to_key))
			continue;

		auto image = boost::get<cryptonote::txin_to_key>(tx_in).k_image;
		inputs.push_back(image);
	}

	return inputs;
}

std::vector<Output> serial_bridge::get_outputs(const cryptonote::transaction &tx)
{
	std::vector<Output> outputs;

	for (size_t i = 0; i < tx.vout.size(); i++) {
		auto tx_out = tx.vout[i];
		
		Output output;
		output.index = i;
		output.amount = std::to_string(tx_out.amount);
		crypto::public_key output_public_key;
		if (!cryptonote::get_output_public_key(tx_out, output_public_key)) continue;
		output.pub = output_public_key;
		output.view_tag = cryptonote::get_output_view_tag(tx_out);
		outputs.push_back(output);
	}

	return outputs;
}

rct::xmr_amount serial_bridge::get_fee(const cryptonote::transaction &tx, const BridgeTransaction &bridge_tx) {
	if (bridge_tx.version == 2) {
		return bridge_tx.rv.txnFee;
	}

	if (bridge_tx.version == 1) {
		rct::xmr_amount fee_amount = 0;

		for (size_t i = 0; i < tx.vin.size(); i++) {
			auto &in = tx.vin[i];
			if (in.type() != typeid(cryptonote::txin_to_key)) continue;

			fee_amount += boost::get<cryptonote::txin_to_key>(in).amount;
		}

		for (size_t i = 0; i < tx.vout.size(); i++) {
			auto &out = tx.vout[i];
			fee_amount -= out.amount;
		}

		return fee_amount;
	}

	return 0;
}

std::string serial_bridge::build_rct(const rct::rctSig &rv, size_t index) {
	switch (rv.type) {
	case rct::RCTTypeSimple:
	case rct::RCTTypeFull:
	case rct::RCTTypeBulletproof:
		return epee::string_tools::pod_to_hex(rv.outPk[index].mask) +
			   epee::string_tools::pod_to_hex(rv.ecdhInfo[index].mask) +
			   epee::string_tools::pod_to_hex(rv.ecdhInfo[index].amount).substr(0, 16);
	case rct::RCTTypeBulletproof2:
	case rct::RCTTypeCLSAG:
	case rct::RCTTypeBulletproofPlus:
		return epee::string_tools::pod_to_hex(rv.outPk[index].mask) +
			   epee::string_tools::pod_to_hex(rv.ecdhInfo[index].amount).substr(0, 16);
	default:
		return "";
	}
}

BridgeTransaction serial_bridge::json_to_tx(boost::property_tree::ptree tx_desc) {
	BridgeTransaction tx;

	tx.id = tx_desc.get<string>("id");

	optional<string> str = tx_desc.get_optional<string>("pub");
	if (str == none) {
		throw std::invalid_argument("Missing 'tx_desc.pub'");
	}
	
	if (!epee::string_tools::hex_to_pod(tx_desc.get<string>("pub"), tx.pub)) {
		throw std::invalid_argument("Invalid 'tx_desc.pub'");
	}

	for (const auto &additional_pub_desc : tx_desc.get_child("additional_pubs")) {
		assert(additional_pub_desc.first.empty());

		std::string pub_str = additional_pub_desc.second.get_value<std::string>();

		crypto::public_key pub;
		if (!epee::string_tools::hex_to_pod(pub_str, pub)) {
			throw std::invalid_argument("Invalid 'tx_desc.additional_pubs.pub'");
		}

		tx.additional_pubs.push_back(pub);
	}

	tx.version = stoul(tx_desc.get<string>("version"));

	auto rv_desc = tx_desc.get_child("rv");
	unsigned int rv_type_int = stoul(rv_desc.get<string>("type"));

	tx.rv = AUTO_VAL_INIT(tx.rv);
	if (rv_type_int == rct::RCTTypeNull) {
		tx.rv.type = rct::RCTTypeNull;
	} else if (rv_type_int == rct::RCTTypeSimple) {
		tx.rv.type = rct::RCTTypeSimple;
	} else if (rv_type_int == rct::RCTTypeFull) {
		tx.rv.type = rct::RCTTypeFull;
	} else if (rv_type_int == rct::RCTTypeBulletproof) {
		tx.rv.type = rct::RCTTypeBulletproof;
	} else if (rv_type_int == rct::RCTTypeBulletproof2) {
		tx.rv.type = rct::RCTTypeBulletproof2;
	} else if (rv_type_int == rct::RCTTypeCLSAG) {
		tx.rv.type = rct::RCTTypeCLSAG;
	} else if (rv_type_int == rct::RCTTypeBulletproofPlus) {
		tx.rv.type = rct::RCTTypeBulletproofPlus;
	} else {
		throw std::invalid_argument("Invalid 'tx_desc.rv.type'");
	}

	BOOST_FOREACH (boost::property_tree::ptree::value_type &ecdh_info_desc, rv_desc.get_child("ecdhInfo")) {
		assert(ecdh_info_desc.first.empty()); // array elements have no names
		auto ecdh_info = rct::ecdhTuple{};
		if (tx.rv.type == rct::RCTTypeBulletproof2 || tx.rv.type == rct::RCTTypeCLSAG || tx.rv.type == rct::RCTTypeBulletproofPlus) {
			if (!epee::string_tools::hex_to_pod(ecdh_info_desc.second.get<string>("amount"), (crypto::hash8 &)ecdh_info.amount))
			{
				throw std::invalid_argument("Invalid 'tx_desc.rv.ecdhInfo[].amount'");
			}
		} else {
			if (!epee::string_tools::hex_to_pod(ecdh_info_desc.second.get<string>("mask"), ecdh_info.mask)) {
				throw std::invalid_argument("Invalid 'tx_desc.rv.ecdhInfo[].mask'");
			} if (!epee::string_tools::hex_to_pod(ecdh_info_desc.second.get<string>("amount"), ecdh_info.amount)) {
				throw std::invalid_argument("Invalid 'tx_desc.rv.ecdhInfo[].amount'");
			}
		}
		tx.rv.ecdhInfo.push_back(ecdh_info); // rct keys aren't movable
	}

	BOOST_FOREACH (boost::property_tree::ptree::value_type &outPk_desc, rv_desc.get_child("outPk")) {
		assert(outPk_desc.first.empty()); // array elements have no names
		auto outPk = rct::ctkey{};
		if (!epee::string_tools::hex_to_pod(outPk_desc.second.get<string>("mask"), outPk.mask)) {
			throw std::invalid_argument("Invalid 'tx_desc.rv.outPk[].mask'");
		}
		tx.rv.outPk.push_back(outPk); // rct keys aren't movable
	}

	uint8_t curr = 0;
	BOOST_FOREACH (boost::property_tree::ptree::value_type &output_desc, tx_desc.get_child("outputs")) {
		assert(output_desc.first.empty()); // array elements have no names
		Output output;
		output.index = curr++;

		if (!epee::string_tools::hex_to_pod(output_desc.second.get<string>("pub"), output.pub)) {
			throw std::invalid_argument("Invalid 'tx_desc.outputs.pub'");
		}

		output.amount = output_desc.second.get<string>("amount");

		crypto::view_tag view_tag = crypto::view_tag{};
		auto viewTagString = output_desc.second.get_optional<string>("view_tag");
		if (viewTagString) {
			bool r = epee::string_tools::hex_to_pod(std::string(*viewTagString), view_tag);
			THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Invalid 'tx_desc.outputs.view_tag'");
			output.view_tag = view_tag;
		}
		tx.outputs.push_back(output);
	}

	return tx;
}
boost::property_tree::ptree serial_bridge::inputs_to_json(std::vector<crypto::key_image> inputs) {
	boost::property_tree::ptree root;

	for (int i = 0; i < inputs.size(); i++) {
		boost::property_tree::ptree input_tree;
		input_tree.put("", epee::string_tools::pod_to_hex(inputs[i]));

		root.push_back(std::make_pair("", input_tree));
	}

	return root;
}
boost::property_tree::ptree serial_bridge::utxos_to_json(std::vector<Utxo> utxos, bool native) {
	boost::property_tree::ptree utxos_ptree;
	BOOST_FOREACH (auto &utxo, utxos) {
		auto out_ptree_pair = std::make_pair("", boost::property_tree::ptree{});
		auto &out_ptree = out_ptree_pair.second;

		out_ptree.put("vout", utxo.vout);
		out_ptree.put("amount", utxo.amount);
		out_ptree.put("key_image", utxo.key_image);
		out_ptree.put("index_major", utxo.index.major);
		out_ptree.put("index_minor", utxo.index.minor);
		out_ptree.put("mask", epee::string_tools::pod_to_hex(utxo.mask));

		if (native) {
			out_ptree.put("pub", epee::string_tools::pod_to_hex(utxo.pub));
			out_ptree.put("global_index", utxo.global_index);
			out_ptree.put("rv", utxo.rv);
		} else {
			out_ptree.put("tx_id", utxo.tx_id);
		}

		utxos_ptree.push_back(out_ptree_pair);
	}

	return utxos_ptree;
}

boost::property_tree::ptree serial_bridge::pruned_block_to_json(const PrunedBlock &pruned_block)
{
	boost::property_tree::ptree block_tree;

	block_tree.put("id", pruned_block.block_height);
	block_tree.put("timestamp", pruned_block.timestamp);

	boost::property_tree::ptree mixins_tree;
	for (int i = 0; i < pruned_block.mixins.size(); i++) {
		auto &mixin = pruned_block.mixins[i];

		boost::property_tree::ptree mixin_tree;
		mixin_tree.put("global_index", mixin.global_index);
		mixin_tree.put("public_key", epee::string_tools::pod_to_hex(mixin.public_key));
		mixin_tree.put("rct", mixin.rct);

		mixins_tree.push_back(std::make_pair("", mixin_tree));
	}

	block_tree.add_child("mixins", mixins_tree);

	return block_tree;
}

string serial_bridge::decode_amount(int version, crypto::key_derivation derivation, rct::rctSig rv, std::string amount, int index, rct::key& mask)
{
	if (version == 1) {
		return amount;
	} else if (version == 2) {
		crypto::secret_key scalar;
		hw::get_device("default").derivation_to_scalar(derivation, index, scalar);

		rct::xmr_amount decoded_amount;

		if (rv.type == rct::RCTTypeFull) {
			decoded_amount = rct::decodeRct(rv, rct::sk2rct(scalar), index, mask, hw::get_device("default"));
		} else if (rv.type == rct::RCTTypeSimple || rv.type == rct::RCTTypeBulletproof || rv.type == rct::RCTTypeBulletproof2 || rv.type == rct::RCTTypeCLSAG || rv.type == rct::RCTTypeBulletproofPlus) {
			decoded_amount = rct::decodeRctSimple(rv, rct::sk2rct(scalar), index, mask, hw::get_device("default"));
		}

		ostringstream decoded_amount_ss;
		decoded_amount_ss << decoded_amount;

		return decoded_amount_ss.str();
	}

	return "";
}
std::vector<Utxo> serial_bridge::extract_utxos_from_tx(BridgeTransaction tx, cryptonote::account_keys account_keys, std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddresses)
{
	hw::device &hwdev = hw::get_device("default");

	std::vector<Utxo> utxos;

	crypto::key_derivation derivation = AUTO_VAL_INIT(derivation);
	if (!crypto::generate_key_derivation(tx.pub, account_keys.m_view_secret_key, derivation)) {
		return utxos;
	}

	std::vector<crypto::key_derivation> additional_derivations;
	for (const auto &pub : tx.additional_pubs) {
		crypto::key_derivation additional_derivation = AUTO_VAL_INIT(additional_derivation);

		if (!crypto::generate_key_derivation(pub, account_keys.m_view_secret_key, additional_derivation))
		{
			return utxos;
		}

		additional_derivations.push_back(additional_derivation);
	}

	BOOST_FOREACH (Output &output, tx.outputs) {
		boost::optional<subaddress_receive_info> subaddr_recv_info = is_out_to_acc_precomp(subaddresses, output.pub, derivation, additional_derivations, output.index, hwdev, output.view_tag);
		if (!subaddr_recv_info) continue;

		Utxo utxo;
		utxo.tx_id = tx.id;
		utxo.index = subaddr_recv_info->index;
		utxo.vout = output.index;
		utxo.amount = serial_bridge::decode_amount(tx.version, subaddr_recv_info->derivation, tx.rv, output.amount, output.index, utxo.mask);
		utxo.tx_pub = tx.pub;
		utxo.pub = output.pub;
		utxo.rv = serial_bridge::build_rct(tx.rv, output.index);

		if (account_keys.m_spend_secret_key != crypto::null_skey) {
			cryptonote::keypair in_ephemeral;
			crypto::key_image ki;

			if(!generate_key_image_helper_precomp(account_keys, output.pub, subaddr_recv_info->derivation, output.index, subaddr_recv_info->index, in_ephemeral, ki, hwdev)) {
				continue;
			}

			utxo.key_image = epee::string_tools::pod_to_hex(ki);
		}

		expand_subaddresses(account_keys, subaddresses, (*subaddr_recv_info).index);

		utxos.push_back(utxo);
	}

	return utxos;
}

ExtractUtxosResponse serial_bridge::extract_utxos_raw(const string &args_string)
{
	ExtractUtxosResponse response;

	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		response.error = error_ret_json_from_message("Invalid JSON");
		return response;
	}

	std::map<std::string, WalletAccountParamsBase> wallet_accounts_params;
	for (const auto& params_desc : json_root.get_child("params_by_wallet_account")) {
		WalletAccountParamsBase wallet_account_params;

		if (!epee::string_tools::hex_to_pod(params_desc.second.get<string>("sec_viewKey_string"), wallet_account_params.account_keys.m_view_secret_key)) {
			continue;
		}

		if (!epee::string_tools::hex_to_pod(params_desc.second.get<string>("pub_spendKey_string"), wallet_account_params.account_keys.m_account_address.m_spend_public_key)) {
			continue;
		}

		wallet_account_params.account_keys.m_spend_secret_key = crypto::null_skey;
		auto secSpendKeyString = params_desc.second.get_optional<string>("sec_spendKey_string");
		if (secSpendKeyString && !epee::string_tools::hex_to_pod(*secSpendKeyString, wallet_account_params.account_keys.m_spend_secret_key)) {
			continue;
		}

		uint32_t subaddresses_count = params_desc.second.get<uint32_t>("subaddresses");

		cryptonote::subaddress_index index = {0, 0};
		expand_subaddresses(wallet_account_params.account_keys, wallet_account_params.subaddresses, index, subaddresses_count);

		wallet_accounts_params.insert(std::make_pair(params_desc.first, wallet_account_params));
	}

	for (const auto &pair : wallet_accounts_params) {
		response.results_by_wallet_account.insert(std::make_pair(pair.first, ExtractUtxosResult{}));
	}

	tools::threadpool& tpool = tools::threadpool::getInstance();
  	tools::threadpool::waiter waiter(tpool);
	struct geniod_params
	{
		const BridgeTransaction &tx;
	};

	auto geniod = [&](const BridgeTransaction &tx) {
		for (auto& pair : wallet_accounts_params) {
			auto tx_utxos = serial_bridge::extract_utxos_from_tx(tx, pair.second.account_keys, pair.second.subaddresses);

			auto &result = response.results_by_wallet_account[pair.first];
			result.utxos.insert(std::end(result.utxos), std::begin(tx_utxos), std::end(tx_utxos));
		}
	};

	for (const auto& tx_desc : json_root.get_child("txs")) {
		assert(tx_desc.first.empty());

		BridgeTransaction tx;
		try {
			tx = serial_bridge::json_to_tx(tx_desc.second);

			// submitting geniod function calls to the thread pool
			tpool.submit(&waiter, [&, tx](){ geniod(tx); }, true);
		} catch(std::invalid_argument err) {
			continue;
		}
	}

	THROW_WALLET_EXCEPTION_IF(!waiter.wait(), error::wallet_internal_error, "Exception in thread pool");

	for (const auto& pair : wallet_accounts_params) {
		auto &result = response.results_by_wallet_account[pair.first];
		result.subaddresses = pair.second.subaddresses.size();
	}

	return response;
}

void serial_bridge::expand_subaddresses(cryptonote::account_keys account_keys, std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddresses, const cryptonote::subaddress_index& tx_index, uint32_t lookahead) {
	if (subaddresses.size() > (tx_index.minor + lookahead - 1)) return;

	hw::device &hwdev = hw::get_device("default");

	const uint32_t begin = subaddresses.size();
	const uint32_t end = get_subaddress_clamped_sum(tx_index.minor, lookahead);

	cryptonote::subaddress_index index = {0, begin};

	const std::vector<crypto::public_key> pkeys = hwdev.get_subaddress_spend_public_keys(account_keys, index.major, index.minor, end);
	for (; index.minor < end; index.minor++) {
		const crypto::public_key &D = pkeys[index.minor - begin];
		subaddresses[D] = index;
	}
}

uint32_t serial_bridge::get_subaddress_clamped_sum(uint32_t idx, uint32_t extra) {
	static constexpr uint32_t uint32_max = std::numeric_limits<uint32_t>::max();
	if (idx > uint32_max - extra)
		return uint32_max;
	return idx + extra;
}
//
//
// Bridge Function Implementations
//
string serial_bridge::decode_address(const string &args_string) {
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		// it will already have thrown an exception
		return error_ret_json_from_message("Invalid JSON");
	}
	auto retVals = monero::address_utils::decodedAddress(json_root.get<string>("address"), nettype_from_string(json_root.get<string>("nettype_string")));
	if (retVals.did_error) {
		return error_ret_json_from_message(*(retVals.err_string));
	}
	boost::property_tree::ptree root;
	root.put(ret_json_key__isSubaddress(), retVals.isSubaddress);
	root.put(ret_json_key__pub_viewKey_string(), *(retVals.pub_viewKey_string));
	root.put(ret_json_key__pub_spendKey_string(), *(retVals.pub_spendKey_string));
	if (retVals.paymentID_string != none) {
		root.put(ret_json_key__paymentID_string(), *(retVals.paymentID_string));
	}
	//
	return ret_json_from_root(root);
}
string serial_bridge::is_subaddress(const string &args_string) {
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		// it will already have thrown an exception
		return error_ret_json_from_message("Invalid JSON");
	}
	bool retVal = monero::address_utils::isSubAddress(json_root.get<string>("address"), nettype_from_string(json_root.get<string>("nettype_string")));
	boost::property_tree::ptree root;
	root.put(ret_json_key__generic_retVal(), retVal);
	//
	return ret_json_from_root(root);
}
string serial_bridge::is_integrated_address(const string &args_string) {
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		// it will already have thrown an exception
		return error_ret_json_from_message("Invalid JSON");
	}
	bool retVal = monero::address_utils::isIntegratedAddress(json_root.get<string>("address"), nettype_from_string(json_root.get<string>("nettype_string")));
	boost::property_tree::ptree root;
	root.put(ret_json_key__generic_retVal(), retVal);
	//
	return ret_json_from_root(root);
}
string serial_bridge::new_integrated_address(const string &args_string)
{
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		// it will already have thrown an exception
		return error_ret_json_from_message("Invalid JSON");
	}
	optional<string> retVal = monero::address_utils::new_integratedAddrFromStdAddr(json_root.get<string>("address"), json_root.get<string>("short_pid"), nettype_from_string(json_root.get<string>("nettype_string")));
	boost::property_tree::ptree root;
	if (retVal != none) {
		root.put(ret_json_key__generic_retVal(), *retVal);
	}
	//
	return ret_json_from_root(root);
}
string serial_bridge::new_payment_id(const string &args_string) {
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		// it will already have thrown an exception
		return error_ret_json_from_message("Invalid JSON");
	}
	optional<string> retVal = monero_paymentID_utils::new_short_plain_paymentID_string();
	boost::property_tree::ptree root;
	if (retVal != none) {
		root.put(ret_json_key__generic_retVal(), *retVal);
	}
	//
	return ret_json_from_root(root);
}
//
string serial_bridge::newly_created_wallet(const string &args_string) {
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		// it will already have thrown an exception
		return error_ret_json_from_message("Invalid JSON");
	}
	monero_wallet_utils::WalletDescriptionRetVals retVals;
	bool r = monero_wallet_utils::convenience__new_wallet_with_language_code(
		json_root.get<string>("locale_language_code"),
		retVals,
		nettype_from_string(json_root.get<string>("nettype_string")));
	bool did_error = retVals.did_error;
	if (!r) {
		return error_ret_json_from_message(*(retVals.err_string));
	}
	THROW_WALLET_EXCEPTION_IF(did_error, error::wallet_internal_error, "Illegal success flag but did_error");
	//
	boost::property_tree::ptree root;
	root.put(
		ret_json_key__mnemonic_string(),
		std::string((*(retVals.optl__desc)).mnemonic_string.data(), (*(retVals.optl__desc)).mnemonic_string.size()));
	root.put(ret_json_key__mnemonic_language(), (*(retVals.optl__desc)).mnemonic_language);
	root.put(ret_json_key__sec_seed_string(), (*(retVals.optl__desc)).sec_seed_string);
	root.put(ret_json_key__address_string(), (*(retVals.optl__desc)).address_string);
	root.put(ret_json_key__pub_viewKey_string(), epee::string_tools::pod_to_hex((*(retVals.optl__desc)).pub_viewKey));
	root.put(ret_json_key__sec_viewKey_string(), epee::string_tools::pod_to_hex((*(retVals.optl__desc)).sec_viewKey));
	root.put(ret_json_key__pub_spendKey_string(), epee::string_tools::pod_to_hex((*(retVals.optl__desc)).pub_spendKey));
	root.put(ret_json_key__sec_spendKey_string(), epee::string_tools::pod_to_hex((*(retVals.optl__desc)).sec_spendKey));
	//
	return ret_json_from_root(root);
}
string serial_bridge::are_equal_mnemonics(const string &args_string) {
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		// it will already have thrown an exception
		return error_ret_json_from_message("Invalid JSON");
	}
	bool equal;
	try {
		equal = monero_wallet_utils::are_equal_mnemonics(
			json_root.get<string>("a"),
			json_root.get<string>("b"));
	}
	catch (std::exception const &e) {
		return error_ret_json_from_message(e.what());
	}
	boost::property_tree::ptree root;
	root.put(ret_json_key__generic_retVal(), equal);
	//
	return ret_json_from_root(root);
}
string serial_bridge::address_and_keys_from_seed(const string &args_string) {
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		// it will already have thrown an exception
		return error_ret_json_from_message("Invalid JSON");
	}
	monero_wallet_utils::ComponentsFromSeed_RetVals retVals;
	bool r = monero_wallet_utils::address_and_keys_from_seed(
		json_root.get<string>("seed_string"),
		nettype_from_string(json_root.get<string>("nettype_string")),
		retVals);
	bool did_error = retVals.did_error;
	if (!r) {
		return error_ret_json_from_message(*(retVals.err_string));
	}
	THROW_WALLET_EXCEPTION_IF(did_error, error::wallet_internal_error, "Illegal success flag but did_error");
	//
	boost::property_tree::ptree root;
	root.put(ret_json_key__address_string(), (*(retVals.optl__val)).address_string);
	root.put(ret_json_key__pub_viewKey_string(), epee::string_tools::pod_to_hex((*(retVals.optl__val)).pub_viewKey));
	root.put(ret_json_key__sec_viewKey_string(), epee::string_tools::pod_to_hex((*(retVals.optl__val)).sec_viewKey));
	root.put(ret_json_key__pub_spendKey_string(), epee::string_tools::pod_to_hex((*(retVals.optl__val)).pub_spendKey));
	root.put(ret_json_key__sec_spendKey_string(), epee::string_tools::pod_to_hex((*(retVals.optl__val)).sec_spendKey));
	//
	return ret_json_from_root(root);
}
string serial_bridge::mnemonic_from_seed(const string &args_string) {
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		// it will already have thrown an exception
		return error_ret_json_from_message("Invalid JSON");
	}
	monero_wallet_utils::SeedDecodedMnemonic_RetVals retVals = monero_wallet_utils::mnemonic_string_from_seed_hex_string(
		json_root.get<string>("seed_string"),
		json_root.get<string>("wordset_name"));
	boost::property_tree::ptree root;
	if (retVals.err_string != none) {
		return error_ret_json_from_message(*(retVals.err_string));
	}
	root.put(
		ret_json_key__generic_retVal(),
		std::string((*(retVals.mnemonic_string)).data(), (*(retVals.mnemonic_string)).size()));
	//
	return ret_json_from_root(root);
}
string serial_bridge::seed_and_keys_from_mnemonic(const string &args_string) {
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		// it will already have thrown an exception
		return error_ret_json_from_message("Invalid JSON");
	}
	monero_wallet_utils::WalletDescriptionRetVals retVals;
	bool r = monero_wallet_utils::wallet_with(
		json_root.get<string>("mnemonic_string"),
		retVals,
		nettype_from_string(json_root.get<string>("nettype_string")));
	bool did_error = retVals.did_error;
	if (!r) {
		return error_ret_json_from_message(*retVals.err_string);
	}
	monero_wallet_utils::WalletDescription walletDescription = *(retVals.optl__desc);
	THROW_WALLET_EXCEPTION_IF(did_error, error::wallet_internal_error, "Illegal success flag but did_error");
	//
	boost::property_tree::ptree root;
	root.put(ret_json_key__sec_seed_string(), (*(retVals.optl__desc)).sec_seed_string);
	root.put(ret_json_key__mnemonic_language(), (*(retVals.optl__desc)).mnemonic_language);
	root.put(ret_json_key__address_string(), (*(retVals.optl__desc)).address_string);
	root.put(ret_json_key__pub_viewKey_string(), epee::string_tools::pod_to_hex((*(retVals.optl__desc)).pub_viewKey));
	root.put(ret_json_key__sec_viewKey_string(), epee::string_tools::pod_to_hex((*(retVals.optl__desc)).sec_viewKey));
	root.put(ret_json_key__pub_spendKey_string(), epee::string_tools::pod_to_hex((*(retVals.optl__desc)).pub_spendKey));
	root.put(ret_json_key__sec_spendKey_string(), epee::string_tools::pod_to_hex((*(retVals.optl__desc)).sec_spendKey));
	//
	return ret_json_from_root(root);
}
string serial_bridge::validate_components_for_login(const string &args_string) {
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		// it will already have thrown an exception
		return error_ret_json_from_message("Invalid JSON");
	}
	monero_wallet_utils::WalletComponentsValidationResults retVals;
	bool r = monero_wallet_utils::validate_wallet_components_with( // returns !did_error
		json_root.get<string>("address_string"),
		json_root.get<string>("sec_viewKey_string"),
		json_root.get_optional<string>("sec_spendKey_string"),
		json_root.get_optional<string>("seed_string"),
		nettype_from_string(json_root.get<string>("nettype_string")),
		retVals);
	bool did_error = retVals.did_error;
	if (!r) {
		return error_ret_json_from_message(*retVals.err_string);
	}
	THROW_WALLET_EXCEPTION_IF(did_error, error::wallet_internal_error, "Illegal success flag but did_error");
	//
	boost::property_tree::ptree root;
	root.put(ret_json_key__isValid(), retVals.isValid);
	root.put(ret_json_key__isInViewOnlyMode(), retVals.isInViewOnlyMode);
	root.put(ret_json_key__pub_viewKey_string(), retVals.pub_viewKey_string);
	root.put(ret_json_key__pub_spendKey_string(), retVals.pub_spendKey_string);
	//
	return ret_json_from_root(root);
}
string serial_bridge::estimated_tx_network_fee(const string &args_string) {
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		// it will already have thrown an exception
		return error_ret_json_from_message("Invalid JSON");
	}
	uint8_t fork_version = 0; // if missing
	optional<string> optl__fork_version_string = json_root.get_optional<string>("fork_version");
	if (optl__fork_version_string != none) {
		fork_version = stoul(*optl__fork_version_string);
	}
	uint64_t fee = monero_fee_utils::estimated_tx_network_fee(
		stoull(json_root.get<string>("fee_per_b")),
		stoul(json_root.get<string>("priority")),
		monero_fork_rules::make_use_fork_rules_fn(fork_version));
	std::ostringstream o;
	o << fee;
	//
	boost::property_tree::ptree root;
	root.put(ret_json_key__generic_retVal(), o.str());
	//
	return ret_json_from_root(root);
}
string serial_bridge::estimate_fee(const string &args_string) {
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		return error_ret_json_from_message("Invalid JSON");
	}
	//
	bool use_per_byte_fee = json_root.get<bool>("use_per_byte_fee");
	bool use_rct = json_root.get<bool>("use_rct");
	int n_inputs = stoul(json_root.get<string>("n_inputs"));
	int mixin = stoul(json_root.get<string>("mixin"));
	int n_outputs = stoul(json_root.get<string>("n_outputs"));
	size_t extra_size = stoul(json_root.get<string>("extra_size"));
	bool bulletproof = json_root.get<bool>("bulletproof");
	bool bulletproof_plus = json_root.get<bool>("bulletproof_plus");
	uint64_t use_view_tags = json_root.get<bool>("use_view_tags");
	uint64_t base_fee = stoull(json_root.get<string>("base_fee"));
	uint64_t fee_quantization_mask = stoull(json_root.get<string>("fee_quantization_mask"));
	uint32_t priority = stoul(json_root.get<string>("priority"));
	uint8_t fork_version = stoul(json_root.get<string>("fork_version"));
	use_fork_rules_fn_type use_fork_rules_fn = monero_fork_rules::make_use_fork_rules_fn(fork_version);
	bool clsag = use_fork_rules_fn(HF_VERSION_CLSAG, -10);
	uint64_t fee_multiplier = monero_fee_utils::get_fee_multiplier(priority, monero_fee_utils::default_priority(), monero_fee_utils::get_fee_algorithm(use_fork_rules_fn), use_fork_rules_fn);
	//
	uint64_t fee = monero_fee_utils::estimate_fee(use_per_byte_fee, use_rct, n_inputs, mixin, n_outputs, extra_size, bulletproof, clsag, bulletproof_plus, use_view_tags, base_fee, fee_quantization_mask);
	//
	std::ostringstream o;
	o << fee;
	boost::property_tree::ptree root;
	root.put(ret_json_key__generic_retVal(), o.str());
	//
	return ret_json_from_root(root);
}
string serial_bridge::estimate_tx_weight(const string &args_string) {
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		return error_ret_json_from_message("Invalid JSON");
	}
	//
	bool use_rct = json_root.get<bool>("use_rct");
	int n_inputs = stoul(json_root.get<string>("n_inputs"));
	int mixin = stoul(json_root.get<string>("mixin"));
	int n_outputs = stoul(json_root.get<string>("n_outputs"));
	size_t extra_size = stoul(json_root.get<string>("extra_size"));
	bool bulletproof = json_root.get<bool>("bulletproof");
	bool clsag = json_root.get<bool>("clsag");
	bool bulletproof_plus = json_root.get<bool>("bulletproof_plus");
	uint64_t use_view_tags = json_root.get<bool>("use_view_tags");
	//
	uint64_t weight = monero_fee_utils::estimate_tx_weight(use_rct, n_inputs, mixin, n_outputs, extra_size, bulletproof, clsag, bulletproof_plus, use_view_tags);
	//
	std::ostringstream o;
	o << weight;
	boost::property_tree::ptree root;
	root.put(ret_json_key__generic_retVal(), o.str());
	//
	return ret_json_from_root(root);
}
string serial_bridge::estimate_rct_tx_size(const string &args_string) {
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		// it will already have thrown an exception
		return error_ret_json_from_message("Invalid JSON");
	}
	std::size_t size = monero_fee_utils::estimate_rct_tx_size(
		stoul(json_root.get<string>("n_inputs")),
		stoul(json_root.get<string>("mixin")),
		stoul(json_root.get<string>("n_outputs")),
		stoul(json_root.get<string>("extra_size")),
		json_root.get<bool>("bulletproof"),
		json_root.get<bool>("clsag"),
		json_root.get<bool>("bulletproof_plus"),
		json_root.get<bool>("use_view_tags"));
	std::ostringstream o;
	o << size;
	//
	boost::property_tree::ptree root;
	root.put(ret_json_key__generic_retVal(), o.str());
	//
	return ret_json_from_root(root);
}
//
string serial_bridge::generate_key_image(const string &args_string) {
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		// it will already have thrown an exception
		return error_ret_json_from_message("Invalid JSON");
	}
	crypto::secret_key sec_viewKey{};
	crypto::secret_key sec_spendKey{};
	crypto::public_key pub_spendKey{};
	crypto::public_key tx_pub_key{}; {
		bool r = false;
		r = epee::string_tools::hex_to_pod(std::string(json_root.get<string>("sec_viewKey_string")), sec_viewKey);
		THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Invalid secret view key");
		r = epee::string_tools::hex_to_pod(std::string(json_root.get<string>("sec_spendKey_string")), sec_spendKey);
		THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Invalid secret spend key");
		r = epee::string_tools::hex_to_pod(std::string(json_root.get<string>("pub_spendKey_string")), pub_spendKey);
		THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Invalid public spend key");
		r = epee::string_tools::hex_to_pod(std::string(json_root.get<string>("tx_pub_key")), tx_pub_key);
		THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Invalid tx pub key");
	}
	monero_key_image_utils::KeyImageRetVals retVals;
	bool r = monero_key_image_utils::new__key_image(
		pub_spendKey, sec_spendKey, sec_viewKey, tx_pub_key,
		stoull(json_root.get<string>("out_index")),
		retVals);
	if (!r) {
		return error_ret_json_from_message("Unable to generate key image"); // TODO: return error string? (unwrap optional)
	}
	boost::property_tree::ptree root;
	root.put(ret_json_key__generic_retVal(), epee::string_tools::pod_to_hex(retVals.calculated_key_image));
	//
	return ret_json_from_root(root);
}
//
string serial_bridge::send_step1__prepare_params_for_get_decoys(const string &args_string) { // TODO: possibly allow this fn to take tx sec key as an arg, although, random bit gen is now handled well by emscripten
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		// it will already have thrown an exception
		return error_ret_json_from_message("Invalid JSON");
	}
	//
	vector<SpendableOutput> unspent_outs;
	BOOST_FOREACH (boost::property_tree::ptree::value_type &output_desc, json_root.get_child("unspent_outs")) {
		assert(output_desc.first.empty()); // array elements have no names
		SpendableOutput out{};
		out.amount = stoull(output_desc.second.get<string>("amount"));
		out.public_key = output_desc.second.get<string>("public_key");
		out.rct = output_desc.second.get_optional<string>("rct");
		if (out.rct != none && (*out.rct).empty() == true) {
			out.rct = none; // just in case it's an empty string, send to 'none' (even though receiving code now handles empty strs)
		}
		out.global_index = stoull(output_desc.second.get<string>("global_index"));
		out.index = stoull(output_desc.second.get<string>("index"));
		out.tx_pub_key = output_desc.second.get<string>("tx_pub_key");
		//
		unspent_outs.push_back(std::move(out));
	}
	optional<string> optl__passedIn_attemptAt_fee_string = json_root.get_optional<string>("passedIn_attemptAt_fee");
	optional<uint64_t> optl__passedIn_attemptAt_fee = none;
	if (optl__passedIn_attemptAt_fee_string != none) {
		optl__passedIn_attemptAt_fee = stoull(*optl__passedIn_attemptAt_fee_string);
	}
	uint8_t fork_version = 0; // if missing
	optional<string> optl__fork_version_string = json_root.get_optional<string>("fork_version");
	if (optl__fork_version_string != none) {
		fork_version = stoul(*optl__fork_version_string);
	}
	Send_Step1_RetVals retVals;
	monero_transfer_utils::send_step1__prepare_params_for_get_decoys(
		retVals,
		//
		json_root.get_optional<string>("payment_id_string"),
		stoull(json_root.get<string>("sending_amount")),
		json_root.get<bool>("is_sweeping"),
		stoul(json_root.get<string>("priority")),
		monero_fork_rules::make_use_fork_rules_fn(fork_version),
		unspent_outs,
		stoull(json_root.get<string>("fee_per_b")), // per v8
		stoull(json_root.get<string>("fee_mask")),
		//
		optl__passedIn_attemptAt_fee // use this for passing step2 "must-reconstruct" return values back in, i.e. re-entry; when nil, defaults to attempt at network min
	);
	boost::property_tree::ptree root;
	if (retVals.errCode != noError) {
		root.put(ret_json_key__any__err_code(), retVals.errCode);
		root.put(ret_json_key__any__err_msg(), err_msg_from_err_code__create_transaction(retVals.errCode));
		//
		// The following will be set if errCode==needMoreMoneyThanFound - and i'm depending on them being 0 otherwise
		root.put(ret_json_key__send__spendable_balance(), RetVals_Transforms::str_from(retVals.spendable_balance));
		root.put(ret_json_key__send__required_balance(), RetVals_Transforms::str_from(retVals.required_balance));
	} else {
		root.put(ret_json_key__send__mixin(), RetVals_Transforms::str_from(retVals.mixin));
		root.put(ret_json_key__send__using_fee(), RetVals_Transforms::str_from(retVals.using_fee));
		root.put(ret_json_key__send__final_total_wo_fee(), RetVals_Transforms::str_from(retVals.final_total_wo_fee));
		root.put(ret_json_key__send__change_amount(), RetVals_Transforms::str_from(retVals.change_amount));
		{
			boost::property_tree::ptree using_outs_ptree;
			BOOST_FOREACH (SpendableOutput &out, retVals.using_outs)
			{ // PROBABLY don't need to shuttle these back (could send only public_key) but consumers might like the feature of being able to send this JSON structure directly back to step2 without reconstructing it for themselves
				auto out_ptree_pair = std::make_pair("", boost::property_tree::ptree{});
				auto &out_ptree = out_ptree_pair.second;
				out_ptree.put("amount", RetVals_Transforms::str_from(out.amount));
				out_ptree.put("public_key", out.public_key);
				if (out.rct != none && (*out.rct).empty() == false)
				{
					out_ptree.put("rct", *out.rct);
				}
				out_ptree.put("global_index", RetVals_Transforms::str_from(out.global_index));
				out_ptree.put("index", RetVals_Transforms::str_from(out.index));
				out_ptree.put("tx_pub_key", out.tx_pub_key);
				using_outs_ptree.push_back(out_ptree_pair);
			}
			root.add_child(ret_json_key__send__using_outs(), using_outs_ptree);
		}
	}
	return ret_json_from_root(root);
}

//
string serial_bridge::pre_step2_tie_unspent_outs_to_mix_outs_for_all_future_tx_attempts(const string &args_string) {
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		// it will already have thrown an exception
		return error_ret_json_from_message("Invalid JSON");
	}
	//
	vector<SpendableOutput> using_outs;
	BOOST_FOREACH(boost::property_tree::ptree::value_type &output_desc, json_root.get_child("using_outs")) {
		assert(output_desc.first.empty()); // array elements have no names
		SpendableOutput out{};
		out.amount = stoull(output_desc.second.get<string>("amount"));
		out.public_key = output_desc.second.get<string>("public_key");
		out.mask = output_desc.second.get<string>("mask");
		out.rct = output_desc.second.get_optional<string>("rct");
		if (out.rct != none && (*out.rct).empty() == true) {
			out.rct = none; // just in case it's an empty string, send to 'none' (even though receiving code now handles empty strs)
		}
		out.global_index = stoull(output_desc.second.get<string>("global_index"));
		out.index = stoull(output_desc.second.get<string>("index"));
		out.tx_pub_key = output_desc.second.get<string>("tx_pub_key");

		for (const auto& additional_pub_desc : output_desc.second.get_child("additional_tx_pubs")) {
			assert(additional_pub_desc.first.empty());

			out.additional_tx_pubs.push_back(additional_pub_desc.second.get_value<std::string>());
		}
		//
		using_outs.push_back(std::move(out));
	}
	//
	vector<RandomAmountOutputs> mix_outs_from_server;
	BOOST_FOREACH(boost::property_tree::ptree::value_type &mix_out_desc, json_root.get_child("mix_outs")) {
		assert(mix_out_desc.first.empty()); // array elements have no names
		auto amountAndOuts = RandomAmountOutputs{};
		amountAndOuts.amount = stoull(mix_out_desc.second.get<string>("amount"));
		BOOST_FOREACH(boost::property_tree::ptree::value_type &mix_out_output_desc, mix_out_desc.second.get_child("outputs"))
		{
			assert(mix_out_output_desc.first.empty()); // array elements have no names
			auto amountOutput = RandomAmountOutput{};
			amountOutput.global_index = stoull(mix_out_output_desc.second.get<string>("global_index"));
			amountOutput.public_key = mix_out_output_desc.second.get<string>("public_key");
			amountOutput.rct = mix_out_output_desc.second.get_optional<string>("rct");
			amountAndOuts.outputs.push_back(std::move(amountOutput));
		}
		mix_outs_from_server.push_back(std::move(amountAndOuts));
	}
	//
	optional<SpendableOutputToRandomAmountOutputs> optl__prior_attempt_unspent_outs_to_mix_outs;
	SpendableOutputToRandomAmountOutputs prior_attempt_unspent_outs_to_mix_outs;
	optional<boost::property_tree::ptree &> optl__prior_attempt_unspent_outs_to_mix_outs_json = json_root.get_child_optional("prior_attempt_unspent_outs_to_mix_outs");
	if (optl__prior_attempt_unspent_outs_to_mix_outs_json != none) {
		BOOST_FOREACH(boost::property_tree::ptree::value_type &outs_to_mix_outs_desc, *optl__prior_attempt_unspent_outs_to_mix_outs_json)
		{
			string out_pub_key = outs_to_mix_outs_desc.first;
			RandomAmountOutputs amountAndOuts{};
			BOOST_FOREACH(boost::property_tree::ptree::value_type &mix_out_output_desc, outs_to_mix_outs_desc.second)
			{
				assert(mix_out_output_desc.first.empty()); // array elements have no names
				auto amountOutput = monero_transfer_utils::RandomAmountOutput{};
				amountOutput.global_index = stoull(mix_out_output_desc.second.get<string>("global_index"));
				amountOutput.public_key = mix_out_output_desc.second.get<string>("public_key");
				amountOutput.rct = mix_out_output_desc.second.get_optional<string>("rct");
				amountAndOuts.outputs.push_back(std::move(amountOutput));
			}
			prior_attempt_unspent_outs_to_mix_outs[out_pub_key] = std::move(amountAndOuts.outputs);
		}
		optl__prior_attempt_unspent_outs_to_mix_outs = std::move(prior_attempt_unspent_outs_to_mix_outs);
	}
	//
	Tie_Outs_to_Mix_Outs_RetVals retVals;
	monero_transfer_utils::pre_step2_tie_unspent_outs_to_mix_outs_for_all_future_tx_attempts(
		retVals,
		//
		using_outs,
		mix_outs_from_server,
		//
		optl__prior_attempt_unspent_outs_to_mix_outs
	);
	boost::property_tree::ptree root;
	if (retVals.errCode != noError) {
		root.put(ret_json_key__any__err_code(), retVals.errCode);
		root.put(ret_json_key__any__err_msg(), err_msg_from_err_code__create_transaction(retVals.errCode));
	} else {
		{
			boost::property_tree::ptree mix_outs_ptree;
			BOOST_FOREACH(RandomAmountOutputs &mix_outs, retVals.mix_outs)
			{
				auto mix_outs_amount_ptree_pair = std::make_pair("", boost::property_tree::ptree{});
				auto& mix_outs_amount_ptree = mix_outs_amount_ptree_pair.second;
				mix_outs_amount_ptree.put("amount", RetVals_Transforms::str_from(mix_outs.amount));
				auto outputs_ptree_pair = std::make_pair("", boost::property_tree::ptree{});
				auto& outputs_ptree = outputs_ptree_pair.second;
				BOOST_FOREACH(RandomAmountOutput &out, mix_outs.outputs)
				{
					auto mix_out_ptree_pair = std::make_pair("", boost::property_tree::ptree{});
					auto& mix_out_ptree = mix_out_ptree_pair.second;
					mix_out_ptree.put("global_index", RetVals_Transforms::str_from(out.global_index));
					mix_out_ptree.put("public_key", out.public_key);
					if (out.rct != none && (*out.rct).empty() == false) {
						mix_out_ptree.put("rct", *out.rct);
					}
					outputs_ptree.push_back(mix_out_ptree_pair);
				}
				mix_outs_amount_ptree.add_child("outputs", outputs_ptree);
				mix_outs_ptree.push_back(mix_outs_amount_ptree_pair);
			}
			root.add_child(ret_json_key__send__mix_outs(), mix_outs_ptree);
		}
		//
		{
			boost::property_tree::ptree prior_attempt_unspent_outs_to_mix_outs_new_ptree;
			for (const auto &out_pub_key_to_mix_outs : retVals.prior_attempt_unspent_outs_to_mix_outs_new)
			{
				auto outs_ptree_pair = std::make_pair(out_pub_key_to_mix_outs.first, boost::property_tree::ptree{});
				auto& outs_ptree = outs_ptree_pair.second;
				for (const auto &mix_out : out_pub_key_to_mix_outs.second)
				{
					auto mix_out_ptree_pair = std::make_pair("", boost::property_tree::ptree{});
					auto& mix_out_ptree = mix_out_ptree_pair.second;
					mix_out_ptree.put("global_index", RetVals_Transforms::str_from(mix_out.global_index));
					mix_out_ptree.put("public_key", mix_out.public_key);
					if (mix_out.rct != none && (*mix_out.rct).empty() == false) {
						mix_out_ptree.put("rct", *mix_out.rct);
					}
					outs_ptree.push_back(mix_out_ptree_pair);
				}
				prior_attempt_unspent_outs_to_mix_outs_new_ptree.push_back(outs_ptree_pair);
			}
			root.add_child(ret_json_key__send__prior_attempt_unspent_outs_to_mix_outs_new(), prior_attempt_unspent_outs_to_mix_outs_new_ptree);
		}
	}
	return ret_json_from_root(root);
}
//
string serial_bridge::send_step2__try_create_transaction(const string &args_string) {
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		// it will already have thrown an exception
		return error_ret_json_from_message("Invalid JSON");
	}
	//
	vector<SpendableOutput> using_outs;
	BOOST_FOREACH(boost::property_tree::ptree::value_type &output_desc, json_root.get_child("using_outs")) {
		assert(output_desc.first.empty()); // array elements have no names
		SpendableOutput out{};
		out.amount = stoull(output_desc.second.get<string>("amount"));
		out.public_key = output_desc.second.get<string>("public_key");
		out.mask = output_desc.second.get<string>("mask");
		out.rct = output_desc.second.get_optional<string>("rct");
		if (out.rct != none && (*out.rct).empty() == true) {
			out.rct = none; // send to 'none' if empty str for safety
		}
		out.global_index = stoull(output_desc.second.get<string>("global_index"));
		out.index = stoull(output_desc.second.get<string>("index"));
		out.tx_pub_key = output_desc.second.get<string>("tx_pub_key");

		for (const auto& additional_pub_desc : output_desc.second.get_child("additional_tx_pubs")) {
			assert(additional_pub_desc.first.empty());

			out.additional_tx_pubs.push_back(additional_pub_desc.second.get_value<std::string>());
		}
		//
		using_outs.push_back(std::move(out));
	}
	vector<RandomAmountOutputs> mix_outs;
	BOOST_FOREACH(boost::property_tree::ptree::value_type &mix_out_desc, json_root.get_child("mix_outs")) {
		assert(mix_out_desc.first.empty()); // array elements have no names
		auto amountAndOuts = RandomAmountOutputs{};
		amountAndOuts.amount = stoull(mix_out_desc.second.get<string>("amount"));
		BOOST_FOREACH(boost::property_tree::ptree::value_type &mix_out_output_desc, mix_out_desc.second.get_child("outputs"))
		{
			assert(mix_out_output_desc.first.empty()); // array elements have no names
			auto amountOutput = RandomAmountOutput{};
			amountOutput.global_index = stoull(mix_out_output_desc.second.get<string>("global_index")); // this is, I believe, presently supplied as a string by the API, probably to avoid overflow
			amountOutput.public_key = mix_out_output_desc.second.get<string>("public_key");
			amountOutput.rct = mix_out_output_desc.second.get_optional<string>("rct");
			amountAndOuts.outputs.push_back(std::move(amountOutput));
		}
		mix_outs.push_back(std::move(amountAndOuts));
	}

	vector<uint64_t> fees;
	BOOST_FOREACH(boost::property_tree::ptree::value_type &fee_desc, json_root.get_child("fees")) {
		assert(fee_desc.first.empty());
		fees.push_back(fee_desc.second.get_value<uint64_t>());
	}

	uint8_t fork_version = 0; // if missing
	optional<string> optl__fork_version_string = json_root.get_optional<string>("fork_version");
	if (optl__fork_version_string != none) {
		fork_version = stoul(*optl__fork_version_string);
	}
	Send_Step2_RetVals retVals;
	monero_transfer_utils::send_step2__try_create_transaction(
		retVals,
		//
		json_root.get<string>("from_address_string"),
		json_root.get<string>("sec_viewKey_string"),
		json_root.get<string>("sec_spendKey_string"),
		json_root.get<string>("to_address_string"),
		json_root.get_optional<string>("payment_id_string"),
		stoull(json_root.get<string>("final_total_wo_fee")),
		stoull(json_root.get<string>("change_amount")),
		stoull(json_root.get<string>("fee_amount")),
		stoul(json_root.get<string>("priority")),
		fees,
		using_outs,
		stoull(json_root.get<string>("fee_per_b")),
		stoull(json_root.get<string>("fee_mask")),
		mix_outs,
		json_root.get<uint32_t>("subaddresses"),
		monero_fork_rules::make_use_fork_rules_fn(fork_version),
		stoull(json_root.get<string>("unlock_time")),
		nettype_from_string(json_root.get<string>("nettype_string"))
	);
	boost::property_tree::ptree root;
	if (retVals.errCode != noError) {
		root.put(ret_json_key__any__err_code(), retVals.errCode);
		root.put(ret_json_key__any__err_msg(), err_msg_from_err_code__create_transaction(retVals.errCode));
	} else {
		if (retVals.tx_must_be_reconstructed) {
			root.put(ret_json_key__send__tx_must_be_reconstructed(), true);
			root.put(ret_json_key__send__fee_actually_needed(), RetVals_Transforms::str_from(retVals.fee_actually_needed)); // must be passed back
		} else {
			root.put(ret_json_key__send__tx_must_be_reconstructed(), false); // so consumers have it available
			root.put(ret_json_key__send__serialized_signed_tx(), *(retVals.signed_serialized_tx_string));
			root.put(ret_json_key__send__tx_hash(), *(retVals.tx_hash_string));
			root.put(ret_json_key__send__tx_key(), *(retVals.tx_key_string));
			root.put(ret_json_key__send__tx_pub_key(), *(retVals.tx_pub_key_string));
		}
	}
	return ret_json_from_root(root);
}
//
string serial_bridge::decodeRct(const string &args_string) {
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		// it will already have thrown an exception
		return error_ret_json_from_message("Invalid JSON");
	}
	rct::key sk;
	if (!epee::string_tools::hex_to_pod(json_root.get<string>("sk"), sk)) {
		return error_ret_json_from_message("Invalid 'sk'");
	}
	unsigned int i = stoul(json_root.get<string>("i"));
	// NOTE: this rv structure parsing could be factored but it presently does not implement a number of sub-components of rv, such as .pseudoOuts
	auto rv_desc = json_root.get_child("rv");
	rct::rctSig rv = AUTO_VAL_INIT(rv);
	unsigned int rv_type_int = stoul(rv_desc.get<string>("type"));
	// got to be a better way to do this
	if (rv_type_int == rct::RCTTypeNull) {
		rv.type = rct::RCTTypeNull;
	} else if (rv_type_int == rct::RCTTypeSimple) {
		rv.type = rct::RCTTypeSimple;
	} else if (rv_type_int == rct::RCTTypeFull) {
		rv.type = rct::RCTTypeFull;
	} else if (rv_type_int == rct::RCTTypeBulletproof) {
		rv.type = rct::RCTTypeBulletproof;
	} else if (rv_type_int == rct::RCTTypeBulletproof2) {
		rv.type = rct::RCTTypeBulletproof2;
	} else if (rv_type_int == rct::RCTTypeCLSAG) {
		rv.type = rct::RCTTypeCLSAG;
	} else if (rv_type_int == rct::RCTTypeBulletproofPlus) {
		rv.type = rct::RCTTypeBulletproofPlus;
	} else {
		return error_ret_json_from_message("Invalid 'rv.type'");
	}
	BOOST_FOREACH (boost::property_tree::ptree::value_type &ecdh_info_desc, rv_desc.get_child("ecdhInfo")) {
		assert(ecdh_info_desc.first.empty()); // array elements have no names
		auto ecdh_info = rct::ecdhTuple{};
		if (!epee::string_tools::hex_to_pod(ecdh_info_desc.second.get<string>("mask"), ecdh_info.mask))
		{
			return error_ret_json_from_message("Invalid rv.ecdhInfo[].mask");
		}
		if (!epee::string_tools::hex_to_pod(ecdh_info_desc.second.get<string>("amount"), ecdh_info.amount))
		{
			return error_ret_json_from_message("Invalid rv.ecdhInfo[].amount");
		}
		rv.ecdhInfo.push_back(ecdh_info); // rct keys aren't movable
	}
	BOOST_FOREACH (boost::property_tree::ptree::value_type &outPk_desc, rv_desc.get_child("outPk")) {
		assert(outPk_desc.first.empty()); // array elements have no names
		auto outPk = rct::ctkey{};
		if (!epee::string_tools::hex_to_pod(outPk_desc.second.get<string>("mask"), outPk.mask))
		{
			return error_ret_json_from_message("Invalid rv.outPk[].mask");
		}
		// FIXME: does dest need to be placed on the key?
		rv.outPk.push_back(outPk); // rct keys aren't movable
	}
	//
	rct::key mask;
	rct::xmr_amount /*uint64_t*/ decoded_amount;
	try {
		decoded_amount = rct::decodeRct(
			rv, sk, i, mask,
			hw::get_device("default") // presently this uses the default device but we could let a string be passed to switch the type
		);
	}
	catch (std::exception const &e) {
		return error_ret_json_from_message(e.what());
	}
	ostringstream decoded_amount_ss;
	decoded_amount_ss << decoded_amount;
	//
	boost::property_tree::ptree root;
	root.put(ret_json_key__decodeRct_mask(), epee::string_tools::pod_to_hex(mask));
	root.put(ret_json_key__decodeRct_amount(), decoded_amount_ss.str());
	//
	return ret_json_from_root(root);
}
//
string serial_bridge::decodeRctSimple(const string &args_string) {
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		// it will already have thrown an exception
		return error_ret_json_from_message("Invalid JSON");
	}
	rct::key sk;
	if (!epee::string_tools::hex_to_pod(json_root.get<string>("sk"), sk)) {
		return error_ret_json_from_message("Invalid 'sk'");
	}
	unsigned int i = stoul(json_root.get<string>("i"));
	// NOTE: this rv structure parsing could be factored but it presently does not implement a number of sub-components of rv, such as .pseudoOuts
	auto rv_desc = json_root.get_child("rv");
	rct::rctSig rv = AUTO_VAL_INIT(rv);
	unsigned int rv_type_int = stoul(rv_desc.get<string>("type"));
	// got to be a better way to do this
	if (rv_type_int == rct::RCTTypeNull) {
		rv.type = rct::RCTTypeNull;
	} else if (rv_type_int == rct::RCTTypeSimple) {
		rv.type = rct::RCTTypeSimple;
	} else if (rv_type_int == rct::RCTTypeFull) {
		rv.type = rct::RCTTypeFull;
	} else if (rv_type_int == rct::RCTTypeBulletproof) {
		rv.type = rct::RCTTypeBulletproof;
	} else if (rv_type_int == rct::RCTTypeBulletproof2) {
		rv.type = rct::RCTTypeBulletproof2;
	} else if (rv_type_int == rct::RCTTypeCLSAG) {
		rv.type = rct::RCTTypeCLSAG;
	} else if (rv_type_int == rct::RCTTypeBulletproofPlus) {
		rv.type = rct::RCTTypeBulletproofPlus;
	} else {
		return error_ret_json_from_message("Invalid 'rv.type'");
	}
	BOOST_FOREACH (boost::property_tree::ptree::value_type &ecdh_info_desc, rv_desc.get_child("ecdhInfo")) {
		assert(ecdh_info_desc.first.empty()); // array elements have no names
		auto ecdh_info = rct::ecdhTuple{};
		if (rv.type == rct::RCTTypeBulletproof2 || rv.type == rct::RCTTypeCLSAG || rv.type == rct::RCTTypeBulletproofPlus)
		{
			if (!epee::string_tools::hex_to_pod(ecdh_info_desc.second.get<string>("amount"), (crypto::hash8 &)ecdh_info.amount))
			{
				return error_ret_json_from_message("Invalid rv.ecdhInfo[].amount");
			}
		}
		else
		{
			if (!epee::string_tools::hex_to_pod(ecdh_info_desc.second.get<string>("mask"), ecdh_info.mask))
			{
				return error_ret_json_from_message("Invalid rv.ecdhInfo[].mask");
			}
			if (!epee::string_tools::hex_to_pod(ecdh_info_desc.second.get<string>("amount"), ecdh_info.amount))
			{
				return error_ret_json_from_message("Invalid rv.ecdhInfo[].amount");
			}
		}
		rv.ecdhInfo.push_back(ecdh_info);
	}
	BOOST_FOREACH (boost::property_tree::ptree::value_type &outPk_desc, rv_desc.get_child("outPk")) {
		assert(outPk_desc.first.empty()); // array elements have no names
		auto outPk = rct::ctkey{};
		if (!epee::string_tools::hex_to_pod(outPk_desc.second.get<string>("mask"), outPk.mask))
		{
			return error_ret_json_from_message("Invalid rv.outPk[].mask");
		}
		// FIXME: does dest need to be placed on the key?
		rv.outPk.push_back(outPk);
	}
	//
	rct::key mask;
	rct::xmr_amount /*uint64_t*/ decoded_amount;
	try {
		decoded_amount = rct::decodeRctSimple(
			rv, sk, i, mask,
			hw::get_device("default") // presently this uses the default device but we could let a string be passed to switch the type
		);
	}
	catch (std::exception const &e) {
		return error_ret_json_from_message(e.what());
	}
	stringstream decoded_amount_ss;
	decoded_amount_ss << decoded_amount;
	//
	boost::property_tree::ptree root;
	root.put(ret_json_key__decodeRct_mask(), epee::string_tools::pod_to_hex(mask));
	root.put(ret_json_key__decodeRct_amount(), decoded_amount_ss.str());
	//
	return ret_json_from_root(root);
}
string serial_bridge::generate_key_derivation(const string &args_string) {
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		// it will already have thrown an exception
		return error_ret_json_from_message("Invalid JSON");
	}
	public_key pub_key;
	if (!epee::string_tools::hex_to_pod(json_root.get<string>("pub"), pub_key)) {
		return error_ret_json_from_message("Invalid 'pub'");
	}
	secret_key sec_key;
	if (!epee::string_tools::hex_to_pod(json_root.get<string>("sec"), sec_key)) {
		return error_ret_json_from_message("Invalid 'sec'");
	}
	crypto::key_derivation derivation = AUTO_VAL_INIT(derivation);
	if (!crypto::generate_key_derivation(pub_key, sec_key, derivation)) {
		return error_ret_json_from_message("Unable to generate key derivation");
	}
	boost::property_tree::ptree root;
	root.put(ret_json_key__generic_retVal(), epee::string_tools::pod_to_hex(derivation));
	//
	return ret_json_from_root(root);
}
string serial_bridge::derive_public_key(const string &args_string) {
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		// it will already have thrown an exception
		return error_ret_json_from_message("Invalid JSON");
	}
	crypto::key_derivation derivation;
	if (!epee::string_tools::hex_to_pod(json_root.get<string>("derivation"), derivation)) {
		return error_ret_json_from_message("Invalid 'derivation'");
	}
	std::size_t output_index = stoul(json_root.get<string>("out_index"));
	crypto::public_key base;
	if (!epee::string_tools::hex_to_pod(json_root.get<string>("pub"), base)) {
		return error_ret_json_from_message("Invalid 'pub'");
	}
	crypto::public_key derived_key = AUTO_VAL_INIT(derived_key);
	if (!crypto::derive_public_key(derivation, output_index, base, derived_key)) {
		return error_ret_json_from_message("Unable to derive public key");
	}
	boost::property_tree::ptree root;
	root.put(ret_json_key__generic_retVal(), epee::string_tools::pod_to_hex(derived_key));
	//
	return ret_json_from_root(root);
}
string serial_bridge::derive_subaddress_public_key(const string &args_string) {
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		// it will already have thrown an exception
		return error_ret_json_from_message("Invalid JSON");
	}
	crypto::key_derivation derivation;
	if (!epee::string_tools::hex_to_pod(json_root.get<string>("derivation"), derivation)) {
		return error_ret_json_from_message("Invalid 'derivation'");
	}
	std::size_t output_index = stoul(json_root.get<string>("out_index"));
	crypto::public_key out_key;
	if (!epee::string_tools::hex_to_pod(json_root.get<string>("output_key"), out_key)) {
		return error_ret_json_from_message("Invalid 'output_key'");
	}
	crypto::public_key derived_key = AUTO_VAL_INIT(derived_key);
	if (!crypto::derive_subaddress_public_key(out_key, derivation, output_index, derived_key)) {
		return error_ret_json_from_message("Unable to derive public key");
	}
	boost::property_tree::ptree root;
	root.put(ret_json_key__generic_retVal(), epee::string_tools::pod_to_hex(derived_key));
	//
	return ret_json_from_root(root);
}
string serial_bridge::derivation_to_scalar(const string &args_string) {
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		// it will already have thrown an exception
		return error_ret_json_from_message("Invalid JSON");
	}
	crypto::key_derivation derivation;
	if (!epee::string_tools::hex_to_pod(json_root.get<string>("derivation"), derivation)) {
		return error_ret_json_from_message("Invalid 'derivation'");
	}
	std::size_t output_index = stoul(json_root.get<string>("output_index"));
	crypto::ec_scalar scalar = AUTO_VAL_INIT(scalar);
	crypto::derivation_to_scalar(derivation, output_index, scalar);
	boost::property_tree::ptree root;
	root.put(ret_json_key__generic_retVal(), epee::string_tools::pod_to_hex(scalar));
	//
	return ret_json_from_root(root);
}
string serial_bridge::encrypt_payment_id(const string &args_string) {
	boost::property_tree::ptree json_root;
	if (!parsed_json_root(args_string, json_root)) {
		// it will already have thrown an exception
		return error_ret_json_from_message("Invalid JSON");
	}
	crypto::hash8 payment_id;
	if (!epee::string_tools::hex_to_pod(json_root.get<string>("payment_id"), payment_id)) {
		return error_ret_json_from_message("Invalid 'payment_id'");
	}
	crypto::public_key public_key;
	if (!epee::string_tools::hex_to_pod(json_root.get<string>("public_key"), public_key)) {
		return error_ret_json_from_message("Invalid 'public_key'");
	}
	crypto::secret_key secret_key;
	if (!epee::string_tools::hex_to_pod(json_root.get<string>("secret_key"), secret_key)) {
		return error_ret_json_from_message("Invalid 'secret_key'");
	}
	hw::device &hwdev = hw::get_device("default");
	hwdev.encrypt_payment_id(payment_id, public_key, secret_key);
	boost::property_tree::ptree root;
	root.put(ret_json_key__generic_retVal(), epee::string_tools::pod_to_hex(payment_id));
	return ret_json_from_root(root);
}
string serial_bridge::extract_utxos(const string &args_string) {
	auto response = serial_bridge::extract_utxos_raw(args_string);

	if (!response.error.empty())
		return response.error;

	boost::property_tree::ptree root;
	boost::property_tree::ptree results_tree;
	for (const auto &pair : response.results_by_wallet_account) {
		boost::property_tree::ptree wallet_tree;
		wallet_tree.add_child("outputs", serial_bridge::utxos_to_json(pair.second.utxos));
		wallet_tree.put("subaddresses", pair.second.subaddresses);

		results_tree.add_child(pair.first, wallet_tree);
	}
	root.add_child("results", results_tree);

	return ret_json_from_root(root);
}
