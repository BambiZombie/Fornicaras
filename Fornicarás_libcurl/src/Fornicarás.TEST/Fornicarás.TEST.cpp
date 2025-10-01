#include "../../Public.hpp"

void runShellcode()
{
    // init curl  
    CURL* curl = curl_easy_init();
    // res code  
    CURLcode res;
    if (curl)
    {
        // set params  
        curl_easy_setopt(curl, CURLOPT_URL, "https://www.jd.com/"); // url  
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false); // if want to use https  
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false); // set peer and host verify false 
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 53210);
        // start req  
        res = curl_easy_perform(curl);
        if (res == CURLE_OK)
        {
            printf("hehe");
            exit(0);
        }
    }
    // release curl  
    curl_easy_cleanup(curl);
}

int main()
{
    runShellcode();
    
    return 0;
}