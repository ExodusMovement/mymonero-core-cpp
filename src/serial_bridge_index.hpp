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
#include "cryptonote_config.h"
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
//
// See serial_bridge_utils.hpp
//
namespace serial_bridge
{
	using namespace std;
	using namespace cryptonote;

	struct Output {
		uint8_t index;
		crypto::public_key pub;
		string amount;
	};

	struct Transaction {
		string id;
		crypto::public_key pub;
		uint8_t version;
		rct::rctSig rv;
		vector<Output> outputs;
	};

	struct Utxo {
		string tx_id;
		uint8_t vout;
		string amount;
		string key_image;
	};

	//
	// Helper Functions
	Transaction json_to_tx(boost::property_tree::ptree tree);
	boost::property_tree::ptree utxos_to_json(vector<Utxo> utxos);
	bool keys_equal(crypto::public_key a, crypto::public_key b);
	string decode_amount(int version, crypto::key_derivation derivation, rct::rctSig rv, string amount, int index);
	vector<Utxo> extract_utxos_from_tx(Transaction tx, crypto::secret_key sec_view_key, crypto::secret_key sec_spend_key, crypto::public_key pub_spend_key);

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
