#include "Cipher.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/rand.h>

#define SALTED_PREFIX    "Salted__"

// ================================================================
// Constructor.
// ================================================================
Cipher::Cipher()
  : m_cipher(CIPHER_DEFAULT_CIPHER),
    m_digest(CIPHER_DEFAULT_DIGEST),
    m_count(CIPHER_DEFAULT_COUNT),
    m_embed(true), // compatible with openssl
    m_debug(false)
{
}

Cipher::~Cipher()
{

}

py::str  Cipher::encryptData(string plainText, string pwd, string salt)
{
    string cipherText = encrypt(plainText,pwd,salt);
    return cipherText;
}

py::str Cipher::decryptData(string cipherText, string pwd, string salt)
{  
    string decryptedText = decrypt(cipherText,pwd,salt);
    return decryptedText;
}

string Cipher::encrypt(const string& plaintext,
		       const string& pass,
		       const string& salt)
{
  set_salt(salt);
  init(pass);
  kv1_t  x     = encode_cipher(plaintext);
  uchar* ct    = x.first;
  uint   ctlen = x.second;
  string ret = encode_base64(ct, ctlen);
  delete [] ct;
  return ret;
}
string Cipher::decrypt(const string& mimetext,
		       const string& pass,
		       const string& salt)
{
  kv1_t  x     = decode_base64(mimetext);
  uchar* ct    = x.first;
  uchar* ctbeg = ct;
  uint   ctlen = x.second;
  if (strncmp((const char*)ct, SALTED_PREFIX, 8) == 0) {
    memcpy(m_salt, &ct[8], 8);
    ct += 16;
    ctlen -= 16;
  }
  else {
    set_salt(salt);
  }
  init(pass);
  string ret = decode_cipher(ct, ctlen);
  delete [] ctbeg;
  return ret;
}

string Cipher::encode_base64(uchar* ciphertext,
			     uint   ciphertext_len) const
{
  BIO* b64 = BIO_new(BIO_f_base64());
  BIO* bm  = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bm);
  if (BIO_write(b64, ciphertext, ciphertext_len)<2) {
    throw runtime_error("BIO_write() failed");
  }
  if (BIO_flush(b64)<1) {
    throw runtime_error("BIO_flush() failed");
  }
  BUF_MEM *bptr=0;
  BIO_get_mem_ptr(b64, &bptr);
  uint len=bptr->length;
  char* mimetext = new char[len+1];
  memcpy(mimetext, bptr->data, bptr->length-1);
  mimetext[bptr->length-1]=0;
  BIO_free_all(b64);

  string ret = mimetext;
  delete [] mimetext;
  return ret;
}
Cipher::kv1_t Cipher::decode_base64(const string& mimetext) const
{
  kv1_t x;
  int SZ=mimetext.size(); // this will always be smaller
  x.first = new uchar[SZ];
  char* tmpbuf = new char[SZ+1];
  strcpy(tmpbuf, mimetext.c_str());
  BIO* b64 = BIO_new(BIO_f_base64());

  // This patch was suggested by Mihai Todor.
  // It was added to the code on 2013-11-21.
  // Please see this post for details:
  //    http://joelinoff.com/blog/?p=664
  if (SZ <= 64) {
    // If the string is less len 64 or less,
    // then the -A switch must be used in
    // openssl.
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  }

  BIO* bm  = BIO_new_mem_buf(tmpbuf, mimetext.size());
  bm = BIO_push(b64, bm);
  x.second = BIO_read(bm, x.first, SZ);
  BIO_free_all(bm);
  delete [] tmpbuf;
  return x;
}	
Cipher::kv1_t Cipher::encode_cipher(const string& plaintext) const
{
  uint SZ = plaintext.size() + AES_BLOCK_SIZE + 20;  // leave some padding
  uchar* ciphertext = new uchar[SZ];
  bzero(ciphertext, SZ);
  uchar* pbeg = ciphertext;

  // This requires some explanation.
  // In order to be compatible with openssl, I need to append
  // 16 characters worth of information that describe the salt.
  // I found this in the openssl source code but I couldn't
  // find any associated documentation.
  uint off = 0;
  if (m_embed) {
    memcpy(&ciphertext[0], SALTED_PREFIX, 8);
    memcpy(&ciphertext[8], m_salt, 8);
    off = 16;
    ciphertext += off;
  }

  int ciphertext_len=0;
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  const EVP_CIPHER* cipher = EVP_aes_256_cbc();
  EVP_CIPHER_CTX_init(ctx);
  if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, m_key, m_iv)) {
    EVP_CIPHER_CTX_free(ctx);
    throw runtime_error("EVP_EncryptInit_ex() init key/iv failed");
  }
  EVP_CIPHER_CTX_set_key_length(ctx, EVP_MAX_KEY_LENGTH);

  // Encrypt the plaintext data all at once.
  // It would be straightforward to chunk it but that
  // add unecesary complexity at this point.
  uchar* pt_buf = (uchar*)plaintext.c_str();
  uint   pt_len = plaintext.size();
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, pt_buf, pt_len)) {
    EVP_CIPHER_CTX_free(ctx);
    throw runtime_error("EVP_EncryptUpdate() failed");
  }

  uchar* pad_buf = ciphertext + ciphertext_len; // pad at the end
  int pad_len=0;
  if (1 != EVP_EncryptFinal_ex(ctx, pad_buf, &pad_len)) {
    EVP_CIPHER_CTX_free(ctx);
    throw runtime_error("EVP_EncryptFinal_ex() failed");
  }

  ciphertext_len += pad_len + off; // <off> for the Salted prefix
  EVP_CIPHER_CTX_free(ctx);
  return kv1_t(pbeg, ciphertext_len);
}
string Cipher::decode_cipher(uchar* ciphertext,
			     uint   ciphertext_len) const
{
  const uint SZ = ciphertext_len+20;
  uchar* plaintext = new uchar[SZ];
  int plaintext_len = 0;
  const EVP_CIPHER* cipher = EVP_aes_256_cbc();
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

  bzero(plaintext, SZ);
  EVP_CIPHER_CTX_init(ctx);

  if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, m_key, m_iv)) {
    EVP_CIPHER_CTX_free(ctx);
    throw runtime_error("EVP_DecryptInit_ex() failed");
  }
  EVP_CIPHER_CTX_set_key_length(ctx, EVP_MAX_KEY_LENGTH);

  if (1 != EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, ciphertext, ciphertext_len)) {
    EVP_CIPHER_CTX_free(ctx);
    throw runtime_error("EVP_DecryptUpdate() failed");
  }

  int plaintext_padlen=0;
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext+plaintext_len, &plaintext_padlen)) {
    EVP_CIPHER_CTX_free(ctx);
    throw runtime_error("EVP_DecryptFinal_ex() failed");
  }
  plaintext_len += plaintext_padlen;
  plaintext[plaintext_len] = 0;

  string ret = (char*)plaintext;
  delete [] plaintext;
  EVP_CIPHER_CTX_free(ctx);
  return ret;
}
void Cipher::set_salt(const string& salt)
{
  if (salt.length() == 0) {
    // Choose a random salt.
    for(uint i=0;i<sizeof(m_salt);++i) {
      m_salt[i] = rand() % 256;
    }
  }
  else if (salt.length() == 8) {
    memcpy(m_salt, salt.c_str(), 8);
  }
  else if (salt.length()<8) {
    throw underflow_error("init(): salt is too short, must be 8 characters");
  }
  else if (salt.length()>8) {
    throw overflow_error("init(): salt is too long, must be 8 characters");
  }
}
void Cipher::init(const string& pass)
{
  // Use a default passphrase if the user didn't specify one.
  m_pass = pass;
  if (m_pass.empty() ) {
    // Default: ' deFau1t pASsw0rD'
    // Obfuscate so that a simple strings will not find it.
    char a[] = {' ', 'd', 'e', 'F', 'a', 'u', '1', 't', ' ',
		'p', 'A', 'S', 's', 'w', '0', 'r', 'D', 0};
    m_pass = a;
  }

  // Create the key and IV values from the passkey.
  bzero(m_key, sizeof(m_key));
  bzero(m_iv, sizeof(m_iv));
  OpenSSL_add_all_algorithms();
  const EVP_CIPHER* cipher = EVP_get_cipherbyname(m_cipher.c_str());
  const EVP_MD*     digest = EVP_get_digestbyname(m_digest.c_str());
  if (!cipher) {
    string msg = "init(): cipher does not exist "+m_cipher;
    throw runtime_error(msg);
  }
  if (!digest) {
    string msg = "init(): digest does not exist "+m_digest;
    throw runtime_error(msg);
  }

  int ks = EVP_BytesToKey(cipher,    // cipher type
			  digest,    // message digest
			  m_salt,    // 8 bytes
			  (uchar*)m_pass.c_str(), // pass value
			  m_pass.length(),
			  m_count,   // number of rounds
			  m_key,
			  m_iv);
  if (ks!=32) {
    throw runtime_error("init() failed: "
			"EVP_BytesToKey did not return a 32 byte key");
  }
}