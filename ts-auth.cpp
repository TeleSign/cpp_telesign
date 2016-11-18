#include <iostream>
#include <string>
#include <vector>
#include <stdlib.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <memory.h>
#include <curl/curl.h>

using namespace std;

typedef unsigned char byte;


static void b64encode(const byte* in, size_t in_len, char** out, size_t* out_len)
{
    BIO *buff, *b64f;
    BUF_MEM *ptr;

    b64f = BIO_new(BIO_f_base64());
    buff = BIO_new(BIO_s_mem());
    buff = BIO_push(b64f, buff);

    BIO_set_flags(buff, BIO_FLAGS_BASE64_NO_NL);
    BIO_set_close(buff, BIO_CLOSE);
    BIO_write(buff, in, in_len);
    BIO_flush(buff);

    BIO_get_mem_ptr(buff, &ptr);
    (*out_len) = ptr->length;
    (*out) = (char *) malloc(((*out_len) + 1) * sizeof(char));
    memcpy(*out, ptr->data, (*out_len));
    (*out)[(*out_len)] = '\0';

    BIO_free_all(buff);
}

static void b64decode(const char* in, size_t in_len, byte** out, size_t* out_len)
{
    BIO *buff, *b64f;

    b64f = BIO_new(BIO_f_base64());
    buff = BIO_new_mem_buf((void *)in, in_len);
    buff = BIO_push(b64f, buff);
    (*out) = (byte *) malloc(in_len * sizeof(char));

    BIO_set_flags(buff, BIO_FLAGS_BASE64_NO_NL);
    BIO_set_close(buff, BIO_CLOSE);
    (*out_len) = BIO_read(buff, (*out), in_len);
    (*out) = (byte *) realloc((void *)(*out), ((*out_len) + 1) * sizeof(byte));
    (*out)[(*out_len)] = '\0';

    BIO_free_all(buff);
}


vector<string> generate_auth_headers(const string &customer_id, const string &secret_key, const string &resource, const string &method, const string &nonce,
                             const string &fields)
{
    // get current date/time
    char date_str[128];
    time_t t;
    time(&t);
    strftime(date_str, 127, "%a, %d %b %Y %H:%M:%S GMT", gmtime(&t));

    // set content type
    string content_type = "";
    if (method == "POST" || method == "PUT")
        content_type = "application/x-www-form-urlencoded";

    // generate string to sign
    string str_to_sign = method + "\n" + content_type + "\n\n" + "x-ts-auth-method:HMAC-SHA256\n" + "x-ts-date:" + date_str + "\n" + "x-ts-nonce:" + nonce;
    if (fields.length() > 0)
        str_to_sign += "\n" + fields;
    str_to_sign += "\n" + resource;

    // decode secret_key
    byte *secret_key_bin = nullptr;
    size_t secret_key_bin_len;
    b64decode(secret_key.c_str(), secret_key.length(), &secret_key_bin, &secret_key_bin_len);

    // get hmac(secret_key, string_to_sign)
    HMAC_CTX ctx;
    unsigned char hmac_buff[2048];
    unsigned int buff_len = 2048;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, secret_key_bin, secret_key_bin_len, EVP_sha256(), NULL);
    HMAC_Update(&ctx, (unsigned char*)str_to_sign.c_str(), str_to_sign.length());
    HMAC_Final(&ctx, hmac_buff, &buff_len);
    HMAC_CTX_cleanup(&ctx);

    delete secret_key_bin;

    // b64 encode signature
    char *signature = nullptr;
    size_t signature_len;
    b64encode(hmac_buff, buff_len, &signature, &signature_len);

    // set result headers
    vector<string> result;
    result.push_back("Authorization: TSA " + customer_id + ":" + string(signature, signature_len));
    result.push_back("x-ts-date: " + string(date_str));
    result.push_back("x-ts-auth-method: HMAC-SHA256");
    result.push_back("x-ts-nonce: " + nonce);

    delete signature;

    return result;
}

int main()
{
    string customer_id = "YOUR_CUSTOMER_ID";
    string api_key = "YOUR_API_KEY (base64 encoded)";
    string resource = "/v1/verify/sms";
    string nonce = "8580b65e-bd80-4ce8-93b8-d611c85dd9c7";	// generate new nonce for each request
    string fields = "phone_number=381600770308&verify_code=1234&template=Template+text&language=en";	// POST fields

    vector<string> auth_headers = generate_auth_headers(customer_id, api_key, resource, "POST", nonce, fields);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL *curl = curl_easy_init();
    CURLcode res;
    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, "https://rest.telesign.com/v1/verify/sms");
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);	// it is recomended to verify host

        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, fields.c_str());

        struct curl_slist *chunk = NULL;
        for (int i = 0; i < auth_headers.size(); i++)
        {
            chunk = curl_slist_append(chunk, auth_headers[i].c_str());
        }

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK)
        {
            cout << "Error: " << curl_easy_strerror(res);
        }

        curl_easy_cleanup(curl);

        curl_slist_free_all(chunk);
    }

    return 0;
}










