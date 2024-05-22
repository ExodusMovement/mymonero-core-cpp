//
// Created by Danh Vo on 16/5/24.
//
#include "extend_helpers.hpp"

using namespace std;

//
using namespace extend_helpers;

void extend_helpers::decode_base64(const string &input, string &out) {
    size_t in_len = input.size();
     if (in_len % 4 != 0 && in_len != 0) {
        throw std::invalid_argument("Input length must be divisible by 4");
    }

    out.clear();
    if (in_len == 0) {
        return; // Return an empty output string if input is empty
    }

    size_t out_len = in_len / 4 * 3;
    if (input[in_len - 1] == '=') out_len--;
    if (input[in_len - 2] == '=') out_len--;

    out.reserve(out_len);

    for (size_t i = 0; i < in_len;) {
        uint32_t a = input[i] == '=' ? 0 : DECODE_TABLE[static_cast<unsigned char>(input[i])]; i++;
        uint32_t b = input[i] == '=' ? 0 : DECODE_TABLE[static_cast<unsigned char>(input[i])]; i++;
        uint32_t c = input[i] == '=' ? 0 : DECODE_TABLE[static_cast<unsigned char>(input[i])]; i++;
        uint32_t d = input[i] == '=' ? 0 : DECODE_TABLE[static_cast<unsigned char>(input[i])]; i++;

        uint32_t triple = (a << 18) + (b << 12) + (c << 6) + d;

        if (out.size() < out_len) out.push_back((triple >> 16) & 0xFF);
        if (out.size() < out_len) out.push_back((triple >> 8) & 0xFF);
        if (out.size() < out_len) out.push_back(triple & 0xFF);
    }
};
