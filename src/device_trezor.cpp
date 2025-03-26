//
// Created by Danh Vo on 26/3/25.
//

#include "device_trezor.hpp"
#include <ringct/rctSigs.h>
#include "string_tools.h"

#include "tools__ret_vals.hpp"

using namespace std;
using namespace epee;
using namespace crypto;

namespace device_trezor{
    void check_computed_key_image(const crypto::public_key& out_key, const crypto::key_image& ki, const std::string signature, tools::RetVals_base& retVals) {     
        retVals = {};

        const char* buff = signature.data();

        if (signature.size() < 64) {
            retVals.did_error = true;
            retVals.err_string = "Signature is too short";
            return;
        }

        crypto::signature sig{};
        memcpy(sig.c.data, buff, 32);
        memcpy(sig.r.data, buff + 32, 32);

        // Verification
        std::vector<const crypto::public_key*> pkeys;
        pkeys.push_back(&out_key);
    
        std::ostringstream ss{};
        if (!(rct::scalarmultKey(rct::ki2rct(ki), rct::curveOrder()) == rct::identity())) {
            retVals.did_error = true;
            ss << "Key image out of validity domain: key image " << epee::string_tools::pod_to_hex(ki);
            retVals.err_string = ss.str();
            return;
        }

        if (!crypto::check_ring_signature((const crypto::hash&)ki, ki, pkeys, &sig)) {
            retVals.did_error = true;
            ss << "Signature failed for key image " << epee::string_tools::pod_to_hex(ki)
                << ", signature " + epee::string_tools::pod_to_hex(sig)
                << ", pubkey " + epee::string_tools::pod_to_hex(*pkeys[0]);
            retVals.err_string = ss.str();
            return;
        }
    }
}