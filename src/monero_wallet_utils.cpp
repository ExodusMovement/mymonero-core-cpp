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
bool monero_wallet_utils::convenience__new_wallet_with_language_code(
	const string &locale_language_code,
	WalletDescriptionRetVals &retVals,
	network_type nettype
) {
	auto mnemonic_language = mnemonic_language_from_code(locale_language_code);
	if (mnemonic_language == none) {
		retVals.did_error = true;
		retVals.err_string = "Unrecognized locale language code";
		return false;
	}
	return new_wallet(*mnemonic_language, retVals, nettype);
}
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
bool monero_wallet_utils::are_equal_mnemonics(const string &words_a, const string &words_b)
{
	bool r;
	//
	MnemonicDecodedSeed_RetVals retVals__a;
	r = decoded_seed(std::move(words_a), retVals__a);
	THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Can't check equality of invalid mnemonic (a)");
	//
	MnemonicDecodedSeed_RetVals retVals__b;
	r = decoded_seed(std::move(words_b), retVals__b);
	THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Can't check equality of invalid mnemonic (b)");
	//
	return *(retVals__a.optl__sec_seed) == *(retVals__b.optl__sec_seed);
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
//
SeedDecodedMnemonic_RetVals monero_wallet_utils::mnemonic_string_from_seed_hex_string(
	const std::string &sec_hexString,
	const std::string &mnemonic_language // aka wordset name
) {
	SeedDecodedMnemonic_RetVals retVals = {};
	//
	epee::wipeable_string mnemonic_string;
	uint32_t sec_hexString_length = sec_hexString.size();
	//
	bool r = false;
	if (sec_hexString_length == sec_seed_hex_string_length) { // normal seed
		crypto::secret_key sec_seed;
		r = string_tools::hex_to_pod(sec_hexString, sec_seed);
		if (!r) {
			retVals.did_error = true;
			retVals.err_string = "Invalid seed";
			return retVals;
		}
		r = crypto::ElectrumWords::bytes_to_words(sec_seed, mnemonic_string, mnemonic_language);
	} else {
		retVals.did_error = true;
		retVals.err_string = "Invalid seed length";
		return retVals;
	}
	if (!r) {
		retVals.did_error = true;
		retVals.err_string = "Couldn't get mnemonic from hex seed";
		return retVals;
	}
	retVals.mnemonic_string = mnemonic_string; // TODO: should/can we just send retVals.mnemonic_string to bytes_to_words ?
	return retVals;
}
//
bool monero_wallet_utils::wallet_with(
	const string &mnemonic_string,
	WalletDescriptionRetVals &retVals,
	cryptonote::network_type nettype
) {
	retVals = {};
	//
	MnemonicDecodedSeed_RetVals decodedSeed_retVals;
	bool r = decoded_seed(mnemonic_string, decodedSeed_retVals);
	if (!r) {
		retVals.did_error = true;
		retVals.err_string = *decodedSeed_retVals.err_string; // TODO: assert?
		return false;
	}
	cryptonote::account_base account{}; // this initializes the wallet and should call the default constructor
	account.generate(
		*decodedSeed_retVals.optl__sec_seed, // is this an extra copy? maybe have consumer pass ref as arg instead
		true/*recover*/,
		false/*two_random*/
	);
	const cryptonote::account_keys& keys = account.get_keys();
	retVals.optl__desc = WalletDescription{
		*decodedSeed_retVals.optl__sec_seed_string, // assumed non nil if r
		//
		account.get_public_address_str(nettype),
		//
		keys.m_spend_secret_key,
		keys.m_view_secret_key,
		keys.m_account_address.m_spend_public_key,
		keys.m_account_address.m_view_public_key,
		//
		*decodedSeed_retVals.optl__mnemonic_string, // assumed non nil if r; copied for return
		*decodedSeed_retVals.mnemonic_language
	};
	return true;
}
bool monero_wallet_utils::address_and_keys_from_seed(
	const string &sec_seed_string,
	network_type nettype,
	ComponentsFromSeed_RetVals &retVals
) {
	retVals = {};
	//
	unsigned long sec_seed_string_length = sec_seed_string.length();
	//
	crypto::secret_key sec_seed;

	if (sec_seed_string_length == sec_seed_hex_string_length) { // normal seed
		bool r = string_tools::hex_to_pod(sec_seed_string, sec_seed);
		if (!r) {
			retVals.did_error = true;
			retVals.err_string = "Invalid seed";
			//
			return false;
		}
	} else {
		retVals.did_error = true;
		retVals.err_string = "Invalid seed";
		//
		return false;
	}
	//
	cryptonote::account_base account{}; // this initializes the wallet and should call the default constructor
	account.generate(
		sec_seed,
		true/*recover*/,
		false/*two_random*/
	);
	const cryptonote::account_keys& keys = account.get_keys();
	retVals.optl__val = ComponentsFromSeed{
		account.get_public_address_str(nettype),
		//
		keys.m_spend_secret_key,
		keys.m_view_secret_key,
		keys.m_account_address.m_spend_public_key,
		keys.m_account_address.m_view_public_key,
	};
	return true;
}
bool monero_wallet_utils::validate_wallet_components_with( // returns !did_error
	const string &address_string,
	const string &sec_viewKey_string,
	optional<string> sec_spendKey_string,
	optional<string> sec_seed_string,
	cryptonote::network_type nettype,
	WalletComponentsValidationResults &retVals
) { // TODO: how can the err_strings be prepared for localization?
	// TODO: return err code instead
	retVals = {};
	bool r = false;
	//
	// Address
	cryptonote::address_parse_info decoded_address_info;
	r = cryptonote::get_account_address_from_str(
		decoded_address_info,
		nettype,
		address_string
	);
	if (r == false) {
		retVals.did_error = true;
		retVals.err_string = "Invalid address";
		//
		return false;
	}
	if (decoded_address_info.is_subaddress) {
		retVals.did_error = true;
		retVals.err_string = "Can't log in with a sub-address";
		//
		return false;
	}
	//
	// View key:
	crypto::secret_key sec_viewKey;
	r = string_tools::hex_to_pod(sec_viewKey_string, sec_viewKey);
	if (r == false) {
		retVals.did_error = true;
		retVals.err_string = "Invalid view key";
		//
		return false;
	}
	// Validate pub key derived from sec view key matches decoded_address-cached pub key
	crypto::public_key expected_pub_viewKey;
	r = crypto::secret_key_to_public_key(sec_viewKey, expected_pub_viewKey);
	if (r == false) {
		retVals.did_error = true;
		retVals.err_string = "Invalid view key";
		//
		return false;
	}
	if (decoded_address_info.address.m_view_public_key != expected_pub_viewKey) {
		retVals.did_error = true;
		retVals.err_string = "Address doesn't match view key";
		//
		return false;
	}
	//
	// View-only vs spend-key/seed
	retVals.isInViewOnlyMode = true; // setting the ground state
	//
	crypto::secret_key sec_spendKey; // may be initialized
	if (sec_spendKey_string != none) {
		// First check if spend key content actually exists before passing to valid_sec_key_from - so that a spend key decode error can be treated as a failure instead of detecting empty spend keys too
		if ((*sec_spendKey_string).empty() == false) {
			r = string_tools::hex_to_pod(*sec_spendKey_string, sec_spendKey);
			if (r == false) { // this is an actual parse error exit condition
				retVals.did_error = true;
				retVals.err_string = "Invalid spend key";
				//
				return false;
			}
			// Validate pub key derived from sec spend key matches decoded_address_info-cached pub key
			crypto::public_key expected_pub_spendKey;
			r = crypto::secret_key_to_public_key(sec_spendKey, expected_pub_spendKey);
			if (r == false) {
				retVals.did_error = true;
				retVals.err_string = "Invalid spend key";
				//
				return false;
			}
			if (decoded_address_info.address.m_spend_public_key != expected_pub_spendKey) {
				retVals.did_error = true;
				retVals.err_string = "Address doesn't match spend key";
				//
				return false;
			}
			retVals.isInViewOnlyMode = false;
		}
	}
	if (sec_seed_string != none) {
		if ((*sec_seed_string).empty() == false) {
			unsigned long sec_seed_string_length = (*sec_seed_string).length();
			crypto::secret_key sec_seed;
			if (sec_seed_string_length == sec_seed_hex_string_length) { // normal seed
				bool r = string_tools::hex_to_pod((*sec_seed_string), sec_seed);
				if (!r) {
					retVals.did_error = true;
					retVals.err_string = "Invalid seed";
					//
					return false;
				}
			} else {
				retVals.did_error = true;
				retVals.err_string = "Invalid seed";
				//
				return false;
			}
			cryptonote::account_base expected_account{}; // this initializes the wallet and should call the default constructor
			expected_account.generate(sec_seed, true/*recover*/, false/*two_random*/);
			const cryptonote::account_keys& expected_account_keys = expected_account.get_keys();
			// TODO: assert sec_spendKey initialized?
			if (expected_account_keys.m_view_secret_key != sec_viewKey) {
				retVals.did_error = true;
				retVals.err_string = "Private view key does not match generated key";
				//
				return false;
			}
			if (expected_account_keys.m_spend_secret_key != sec_spendKey) {
				retVals.did_error = true;
				retVals.err_string = "Private spend key does not match generated key";
				//
				return false;
			}
			if (expected_account_keys.m_account_address.m_view_public_key != decoded_address_info.address.m_view_public_key) {
				retVals.did_error = true;
				retVals.err_string = "Public view key does not match generated key";
				//
				return false;
			}
			if (expected_account_keys.m_account_address.m_spend_public_key != decoded_address_info.address.m_spend_public_key) {
				retVals.did_error = true;
				retVals.err_string = "Public spend key does not match generated key";
				//
				return false;
			}
			//
			retVals.isInViewOnlyMode = false; // TODO: should this ensure that sec_spendKey is not nil? spendKey should always be available if the seed is…
		}
	}
	retVals.pub_viewKey_string = string_tools::pod_to_hex(decoded_address_info.address.m_view_public_key);
	retVals.pub_spendKey_string = string_tools::pod_to_hex(decoded_address_info.address.m_spend_public_key);
	retVals.isValid = true;
	//
	return true;
}
