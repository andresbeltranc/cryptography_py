#include <iostream>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include "openssl/err.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <cstring>
#include <iostream>
#include <pybind11/pybind11.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <stdint.h>
#include <string>
using namespace std;
namespace py = pybind11;

#define CIPHER_DEFAULT_CIPHER "aes-256-cbc"
#define CIPHER_DEFAULT_DIGEST "sha256"
#define CIPHER_DEFAULT_COUNT  1

class Cipher
{

public:
    // string key,string iv)
     Cipher();
     //Cipher(const string& cipher,const string& digest, uint count=1, bool embed=true);
    ~Cipher();

    typedef unsigned int uint;
    typedef unsigned char uchar;
    typedef uchar aes_key_t[32];
    typedef uchar aes_iv_t[32];
    typedef uchar aes_salt_t[8];
    typedef std::pair<unsigned char*,uint> kv1_t;


    py::str  encryptData(string plainText, string pwd, string salt);
    py::str  decryptData(string cipherText, string pwd, string salt);


private:
    void handleErrors(void);
    string decrypt(string passphrase, kv1_t data);  
    string encrypt( string passphrase,  string data);
    string m_pass;
    string m_cipher;
    string m_digest;
    aes_salt_t  m_salt;
    aes_key_t   m_key;
    aes_iv_t    m_iv;
    uint        m_count;
    bool        m_embed;
    bool        m_debug;
    
    void init(const std::string& pass);
    string encrypt(const std::string& plaintext, const std::string& pass="", const std::string& salt="");
    string decrypt(const std::string& ciphertext, const std::string& pass="",const std::string& salt="");

    string encode_base64(uchar* ciphertext, uint   ciphertext_len) const;
    kv1_t decode_base64(const string& mimetext) const;

    kv1_t encode_cipher(const std::string& plaintext) const;
    string decode_cipher(uchar* ciphertext, uint   ciphertext_len) const;

    void set_salt(const std::string& salt);
    







};
