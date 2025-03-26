#ifndef MONERO_DEVICE_TREZOR_H
#define MONERO_DEVICE_TREZOR_H

#include "crypto.h"
#include "tools__ret_vals.hpp"

namespace device_trezor {
    using namespace std;
    
    void check_computed_key_image(const crypto::public_key& out_key, const crypto::key_image &ki, const std::string signature, tools::RetVals_base& retVals) ;
}

#endif //MONERO_DEVICE_TREZOR_H
