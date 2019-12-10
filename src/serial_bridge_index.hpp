//
//  serial_bridge_index.hpp
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

#ifndef serial_bridge_index_hpp
#define serial_bridge_index_hpp
//
#include <string>
#include <boost/property_tree/ptree.hpp>
#include "rpc/core_rpc_server_commands_defs.h"
#include "cryptonote_config.h"
#include "cryptonote_basic/tx_extra.h"
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
//
// See serial_bridge_utils.hpp
//
namespace serial_bridge
{
	using namespace std;
	using namespace cryptonote;

	struct output {
		uint8_t index;
		crypto::public_key pub;
		string amount;
	};

	struct utxo_base {
		string tx_id;
		uint8_t vout;
		string amount;
		string key_image;
	};

	struct utxo: public utxo_base {
		crypto::public_key tx_pub;
		crypto::public_key pub;
		std::string rv;
		uint64_t global_index;
		uint64_t block_height;
	};

	struct bridge_tx {
		std::string id;
		uint8_t version;
		uint64_t timestamp;
		uint64_t block_height;
		rct::rctSig rv;
		crypto::public_key pub;
		crypto::hash payment_id = crypto::null_hash;
		crypto::hash8 payment_id8 = crypto::null_hash8;
		rct::xmr_amount fee_amount = 0;
		std::vector<crypto::key_image> inputs;
		std::vector<output> outputs;
		std::vector<utxo> utxos;
	};

	struct mixin {
		uint64_t global_index;
		crypto::public_key public_key;
		std::string rct;
	};

	struct pruned_block {
		uint64_t block_height;
		uint64_t timestamp;
		std::vector<mixin> mixins;
	};

	struct native_response {
		std::string error;
		uint64_t current_height;
		uint64_t end_height = 0;
		std::vector<bridge_tx> txs;
		uint64_t latest;
		uint64_t oldest;
		uint64_t size;
	};

	//
	// HTTP helpers
	const char *create_blocks_request(int height, size_t *length);
	native_response extract_data_from_blocks_response(const char *buffer, size_t length, const string &args_string);
	std::string extract_data_from_blocks_response_str(const char *buffer, size_t length, const string &args_string);

	//
	// Helper Functions
	crypto::public_key get_extra_pub_key(const std::vector<cryptonote::tx_extra_field> &fields);
	std::string get_extra_nonce(const std::vector<cryptonote::tx_extra_field> &fields);
	std::vector<crypto::key_image> get_inputs(const cryptonote::transaction &tx, const bridge_tx &bridge_tx, std::map<std::string, bool> &gki);
	std::vector<output> get_outputs(const cryptonote::transaction &tx);
	rct::xmr_amount get_fee(const cryptonote::transaction &tx, const bridge_tx &bridge_tx);
	std::string build_rct(const rct::rctSig &rv, size_t index);
	bridge_tx json_to_tx(boost::property_tree::ptree tree);
	boost::property_tree::ptree inputs_to_json(std::vector<crypto::key_image> inputs);
	boost::property_tree::ptree utxos_to_json(std::vector<utxo> utxos, bool native = false);
	boost::property_tree::ptree pruned_block_to_json(const pruned_block &pruned_block);
	bool keys_equal(crypto::public_key a, crypto::public_key b);
	std::string decode_amount(int version, crypto::key_derivation derivation, rct::rctSig rv, std::string amount, int index);
	std::vector<utxo> extract_utxos_from_tx(bridge_tx tx, crypto::secret_key sec_view_key, crypto::secret_key sec_spend_key, crypto::public_key pub_spend_key);

	//
	// Bridging Functions - these take and return JSON strings
	string send_step1__prepare_params_for_get_decoys(const string &args_string);
	string send_step2__try_create_transaction(const string &args_string);
	//
	string decode_address(const string &args_string);
	string is_subaddress(const string &args_string);
	string is_integrated_address(const string &args_string);
	//
	string new_integrated_address(const string &args_string);
	string new_payment_id(const string &args_string);
	//
	string newly_created_wallet(const string &args_string);
	string are_equal_mnemonics(const string &args_string);
	string address_and_keys_from_seed(const string &args_string); // aka legacy mymonero-core-js:create_address
	string mnemonic_from_seed(const string &args_string);
	string seed_and_keys_from_mnemonic(const string &args_string);
	string validate_components_for_login(const string &args_string);
	//
	string estimated_tx_network_fee(const string &args_string);
	string estimate_fee(const string &args_string);
	string estimate_tx_weight(const string &args_string);
	string estimate_rct_tx_size(const string &args_string);
	//
	string generate_key_image(const string &args_string);
	//
	string generate_key_derivation(const string &args_string);
	string derive_public_key(const string &args_string);
	string derive_subaddress_public_key(const string &args_string);
	string derivation_to_scalar(const string &args_string);
	string decodeRct(const string &args_string);
	string decodeRctSimple(const string &args_string);
	string encrypt_payment_id(const string &args_string);
	//
	string extract_utxos(const string &args_string);
}

#endif /* serial_bridge_index_hpp */
