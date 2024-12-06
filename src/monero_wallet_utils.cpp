//
//  monero_wallet_utils.cpp
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
#include "monero_wallet_utils.hpp"
#include <boost/algorithm/string.hpp>
#include "cryptonote_basic.h"
#include "cryptonote_basic/account.h"
#include "wallet_errors.h" // not crazy about including this but it's not that bad
#include "keccak.h"
//
#include "string_tools.h"
using namespace epee;
//
extern "C" {
	#include "crypto-ops.h"
}
//
using namespace monero_wallet_utils;
using namespace crypto; // for extension
//
bool monero_wallet_utils::new_wallet(
    const string &mnemonic_language,
	WalletDescriptionRetVals &retVals,
	network_type nettype
) {
	retVals = {};
	//
	cryptonote::account_base account{}; // this initializes the wallet and should call the default constructor
	crypto::secret_key nonLegacy32B_sec_seed = account.generate();
	//
	const cryptonote::account_keys& keys = account.get_keys();
	std::string address_string = account.get_public_address_str(nettype); // getting the string here instead of leaving it to the consumer b/c get_public_address_str could potentially change in implementation (see TODO) so it's not right to duplicate that here
	//
	epee::wipeable_string mnemonic_string;
	bool r = crypto::ElectrumWords::bytes_to_words(nonLegacy32B_sec_seed, mnemonic_string, mnemonic_language);
	// ^-- it's OK to directly call ElectrumWords w/ crypto::secret_key as we are generating new wallet, not reading
	if (!r) {
		retVals.did_error = true;
		retVals.err_string = "Unable to create new wallet";
		// TODO: return code of unable to convert seed to mnemonic
		//
		return false;
	}
	retVals.optl__desc = WalletDescription{
		string_tools::pod_to_hex(nonLegacy32B_sec_seed),
		//
		address_string,
		//
		keys.m_spend_secret_key,
		keys.m_view_secret_key,
		keys.m_account_address.m_spend_public_key,
		keys.m_account_address.m_view_public_key,
		//
		mnemonic_string,
		mnemonic_language
	};
	return true;
}
//
const uint32_t stable_32B_seed_mnemonic_word_count = 25;

bool _areBothSpaceChars(char lhs, char rhs) {
	return lhs == rhs && lhs == ' ';
}
bool monero_wallet_utils::decoded_seed(
	const epee::wipeable_string &arg__mnemonic_string__ref,
	MnemonicDecodedSeed_RetVals &retVals
) {
	retVals = {};
	//
	// sanitize inputs
	if (arg__mnemonic_string__ref.empty()) {
		retVals.did_error = true;
		retVals.err_string = "Please enter a valid seed";
		//
		return false;
	}
	string mnemonic_string = string(arg__mnemonic_string__ref.data(), arg__mnemonic_string__ref.size()); // just going to take a copy rather than require people to pass mutable string in.
	// input sanitization
	boost::algorithm::to_lower(mnemonic_string); // critical
	//
	// converting undesireable whitespace chars to spaces, then removing redundant spaces (this ensures "word\nword"->"word word"
	std::replace(mnemonic_string.begin(), mnemonic_string.end(), '\r', ' ');
	std::replace(mnemonic_string.begin(), mnemonic_string.end(), '\n', ' ');
	std::replace(mnemonic_string.begin(), mnemonic_string.end(), '\t', ' ');
	std::string::iterator new_end = std::unique(mnemonic_string.begin(), mnemonic_string.end(), _areBothSpaceChars);
	mnemonic_string.erase(new_end, mnemonic_string.end());
	//
	// FIXME: any other input sanitization to do here?
	//
	const epee::wipeable_string &mnemonic_string__ref = mnemonic_string; // re-obtain wipeable_string ref
	std::istringstream stream(mnemonic_string); // to count words…
	unsigned long word_count = std::distance(std::istream_iterator<std::string>(stream), std::istream_iterator<std::string>());
	//	unsigned long word_count = boost::range::distance(boost::algorithm::make_split_iterator(mnemonic_string, boost::algorithm::is_space())); // TODO: get this workin
	//
	secret_key sec_seed;
	string sec_seed_string; // TODO/FIXME: needed this for shared ref outside of if branch below… not intending extra default constructor call but not sure how to get around it yet
	string mnemonic_language;
	if (word_count == stable_32B_seed_mnemonic_word_count) {
		bool r = crypto::ElectrumWords::words_to_bytes(mnemonic_string__ref, sec_seed, mnemonic_language);
		if (!r) {
			retVals.did_error = true;
			retVals.err_string = "Invalid 25-word mnemonic";
			//
			return false;
		}
		sec_seed_string = string_tools::pod_to_hex(sec_seed);
	} else {
		retVals.did_error = true;
		retVals.err_string = "Please enter a 25- or 13-word secret mnemonic.";
		//
		return false;
	}
	retVals.mnemonic_language = mnemonic_language;
	retVals.optl__sec_seed = sec_seed;
	retVals.optl__sec_seed_string = sec_seed_string;
	retVals.optl__mnemonic_string = mnemonic_string; 
	//
	return true;
}
