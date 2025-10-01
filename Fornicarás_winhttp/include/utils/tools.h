#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <fstream>
#include <iterator>
#include <windows.h>


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

LPCWSTR stringToLPCWSTR(std::string orig)
{
	size_t origsize = orig.length() + 1;
	const size_t newsize = 100;
	size_t convertedChars = 0;
	wchar_t *wcstring = (wchar_t *)malloc(sizeof(wchar_t)*(orig.length() - 1));
	mbstowcs_s(&convertedChars, wcstring, origsize, orig.c_str(), _TRUNCATE);

	return wcstring;
}

void* mc(void* dest, const void* src, size_t n) 
{
	char* d = (char*)dest;
	const char* s = (const char*)src;
	while (n--)
		*d++ = *s++;
	return dest;
}