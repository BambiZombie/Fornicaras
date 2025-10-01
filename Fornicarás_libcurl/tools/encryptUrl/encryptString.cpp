#include "utils/b64_rc4_hex.h"

int main()
{
    std::string str = "https://abc.nbch1na.com:2087/download/image.jpg";
    std::string hex_string = hex_encode(str);
    std::cout << base64_encode(hex_string) << std::endl;

    return 0;
}