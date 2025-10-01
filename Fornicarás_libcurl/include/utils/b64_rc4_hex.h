#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <fstream>
#include <iterator>

static inline bool is_base64(unsigned char c) 
{
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_encode(const std::string& input) 
{
    const std::string base64Chars = "i5jLW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tAxUrFlVPzhmow9BHCMDpEaJRZN";
    std::string encodedString;
    size_t inputSize = input.size();
    size_t i = 0;

    while (i < inputSize) {
        unsigned char char1 = input[i++];
        unsigned char char2 = (i < inputSize) ? input[i++] : 0;
        unsigned char char3 = (i < inputSize) ? input[i++] : 0;

        unsigned char b1 = char1 >> 2;
        unsigned char b2 = ((char1 & 0x3) << 4) | (char2 >> 4);
        unsigned char b3 = ((char2 & 0xF) << 2) | (char3 >> 6);
        unsigned char b4 = char3 & 0x3F;

        encodedString += base64Chars[b1];
        encodedString += base64Chars[b2];
        encodedString += (char2 ? base64Chars[b3] : '=');
        encodedString += (char3 ? base64Chars[b4] : '=');
    }

    return encodedString;
}

std::string base64_decode(const std::string& encoded_string) 
{
    const std::string base64_chars = "i5jLW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tAxUrFlVPzhmow9BHCMDpEaJRZN";
    size_t in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string ret;

    while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]) & 0xff;

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xF) << 4) + ((char_array_4[2] & 0x3C) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret += char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (j = 0; j < i; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]) & 0xff;

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xF) << 4) + ((char_array_4[2] & 0x3C) >> 2);

        for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
    }

    return ret;
}

std::string hex_encode(const std::string& input) 
{
    std::stringstream encoded;
    encoded << std::hex << std::setfill('0');

    for (unsigned char c : input) {
        encoded << std::setw(2) << static_cast<int>(c);
    }

    return encoded.str();
}

std::string hex_decode(const std::string& input) 
{
    std::stringstream decoded;

    std::vector<unsigned char> decoded_data;

    for (size_t i = 0; i < input.length(); i += 2) {
        std::string byte_str = input.substr(i, 2);
        unsigned int byte_value = std::stoul(byte_str, nullptr, 16);
        decoded_data.push_back(static_cast<unsigned char>(byte_value));
    }

    copy(decoded_data.begin(), decoded_data.end(), std::ostream_iterator<unsigned char>(decoded, ""));
    return decoded.str();
}

std::string rc4_encrypt_decrypt(const std::string& data, const std::string& key) 
{
    std::string result;
    result.reserve(data.size());

    std::vector<unsigned char> state(512);
    for (int i = 0; i < 512; ++i) {
        state[i] = i;
    }

    int j = 0;
    int keyLength = key.size();

    for (int i = 0; i < 512; ++i) {
        j = (j + state[i] + key[i % keyLength]) % 512;
        std::swap(state[i], state[j]);
    }

    int i = 0;
    j = 0;

    for (char c : data) {
        i = (i + 1) % 512;
        j = (j + state[i]) % 512;
        std::swap(state[i], state[j]);
        result += c ^ state[(state[i] + state[j]) % 512];
    }

    return result;
}

std::string read_file(const std::string& filepath) 
{
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        return "";
    }

    std::stringstream buffer;
    buffer << file.rdbuf();

    return buffer.str();
}
