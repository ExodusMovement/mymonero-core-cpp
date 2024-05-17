//
// Created by Danh Vo on 16/5/24.
//
#include "extend_helpers.hpp"

using namespace std;

//
using namespace extend_helpers;

string extend_helpers::decode_base64(const string &input, string &out) {
    size_t in_len = input.size();
    if (in_len % 4 != 0)
        return "Input data size is not a multiple of 4";

    size_t out_len = in_len / 4 * 3;
    if (in_len >= 1 && input[in_len - 1] == '=')
        out_len--;
    if (in_len >= 2 && input[in_len - 2] == '=')
        out_len--;

    out.resize(out_len);

    for (size_t i = 0, j = 0; i < in_len;) {
        uint32_t a = input[i] == '='
                     ? 0 & i++
                     : kDecodingTable[static_cast<int>(input[i++])];
        uint32_t b = input[i] == '='
                     ? 0 & i++
                     : kDecodingTable[static_cast<int>(input[i++])];
        uint32_t c = input[i] == '='
                     ? 0 & i++
                     : kDecodingTable[static_cast<int>(input[i++])];
        uint32_t d = input[i] == '='
                     ? 0 & i++
                     : kDecodingTable[static_cast<int>(input[i++])];

        uint32_t triple =
                (a << 3 * 6) + (b << 2 * 6) + (c << 1 * 6) + (d << 0 * 6);

        if (j < out_len)
            out[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < out_len)
            out[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < out_len)
            out[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return "";
};
