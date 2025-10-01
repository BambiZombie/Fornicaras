#include "utils/b64_rc4_hex.h"
#include "utils/tools.h"

int main()
{
    std::string filename = "beacon.bin";
    std::string key = "0123456789abcdefghijklmnopqrstuv";
    std::string enc_file = rc4_encrypt_decrypt(read_file(filename), key);

    std::string hex_string = hex_encode(enc_file);
    std::cout << base64_encode(hex_string) << std::endl;

    return 0;
}