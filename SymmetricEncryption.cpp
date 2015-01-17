#include "SymmetricEncryption.h"
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <cassert>

// ERR_get_error ERR_error_string

static const EVP_CIPHER *getCipher (const char *optional_cipher_name) {
	if (!optional_cipher_name || optional_cipher_name[0] == '\0'
		|| strcmp(optional_cipher_name, "aes-256-gcm") == 0)
	{
		return EVP_aes_256_gcm();
	}
	const EVP_CIPHER *cipher = EVP_get_cipherbyname(optional_cipher_name);
	if (!cipher)
		throw std::runtime_error ("Could not find requested cipher: " + std::string(optional_cipher_name));
	return cipher;
}

static const EVP_MD *getHashAlgo (const char *optional_cipher_name) {
	if (!optional_cipher_name || optional_cipher_name[0] == '\0'
		|| strcmp(optional_cipher_name, "sha-256") == 0)
	{
		return EVP_sha256();
	}
	const EVP_MD *algo = EVP_get_digestbyname(optional_cipher_name);
	if (!algo)
		throw std::runtime_error ("Could not find requested hash algorithm: " + std::string(optional_cipher_name));
	return algo;
}

namespace JpsNet {
namespace Crypt {

const char *DEFAULT_CIPHER = "aes-256-gcm";
const char *DEFAULT_HASH_ALGORITHM = "sha-256";

enum InternalCryptState : char {
	CRYPT_S_UNINITIALIZED = 0,
	CRYPT_S_CREATED = 1,
	CRYPT_S_INITIALIZED = 2,
	CRYPT_S_UPDATE = 3,
	CRYPT_S_FINALIZED = 4
};

static void validate_key_and_iv (const std::string &key, const std::string &iv, const EVP_CIPHER *cipher) {
	if (iv.size() < (size_t)EVP_CIPHER_iv_length(cipher))
		throw std::runtime_error ("Crypt: IV is too short for selected cipher");
	if (key.size() < (size_t)EVP_CIPHER_key_length(cipher))
		throw std::runtime_error ("Crypt: Key is too short for selected cipher");
}

Encryption::Encryption (const char *cipher_name) : state(CRYPT_S_CREATED), out(&defaultOut) {
	this->cipher = getCipher(cipher_name);
	this->ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		throw std::runtime_error ("Failed to create encryption context: ");
	out->reserve(EVP_CIPHER_block_size(cipher) * 4 + 1); // some reserve
}

Encryption::Encryption (Encryption &&o) : cipher(o.cipher), ctx(o.ctx),
	state(o.state), defaultOut(std::move(o.defaultOut)), out(o.out)
{
	o.state = CRYPT_S_UNINITIALIZED;
	o.ctx = nullptr;
}

Encryption::~Encryption () {
	// Can only be null if this object was moved from
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
}

void Encryption::setOutputBuffer (std::string *pOut) {
	if (!pOut)
		this->out = &defaultOut;
	else
		this->out = pOut;
}

void Encryption::init (const std::string &key, const std::string &iv) {
	if (state != CRYPT_S_CREATED && state != CRYPT_S_FINALIZED)
		throw std::logic_error ("Encryption::init: Invalid state");
	validate_key_and_iv(key, iv, cipher);
	out->clear();
	if (EVP_EncryptInit(ctx, cipher, nullptr, nullptr) != 1) {
		throw std::runtime_error ("Failed to initialize encryption cipher: " + getCryptError());
	}
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL) != 1)
		throw std::runtime_error ("Failed to set cipher iv length: " + getCryptError());
	if (EVP_EncryptInit(ctx, nullptr, (const unsigned char*)key.c_str(),
		(const unsigned char*)iv.c_str()) != 1) {
		throw std::runtime_error ("Failed to initialize encryption: " + getCryptError());
	}
	state = CRYPT_S_INITIALIZED;
}

void Encryption::feed (const void *mem, int length) {
	if (state != CRYPT_S_INITIALIZED && state != CRYPT_S_UPDATE)
		throw std::logic_error ("Encryption::feed: Invalid state");
	int outLen = length * 2;
	unsigned char block[outLen];
	if (EVP_EncryptUpdate(ctx, block, &outLen, (unsigned char*)mem, length) != 1)
		throw std::runtime_error ("Failed to encrypt data: "+ getCryptError());
	out->append ((const char*)block, outLen);
	state = CRYPT_S_UPDATE;
}

const std::string &Encryption::finalize () {
	if (state != CRYPT_S_UPDATE)
		throw std::logic_error ("Encryption::finalize: Invalid state");
	int outLen = EVP_CIPHER_block_size(EVP_CIPHER_CTX_cipher(ctx)) + 1;
	unsigned char block[outLen];
	if (EVP_EncryptFinal_ex(ctx, block, &outLen) != 1)
		throw std::runtime_error ("Failed to finalize data encryption: "+ getCryptError());
	if (EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LENGTH, ctag) != 1)
		throw std::runtime_error ("Failed to fetch tag after encryption: "+ getCryptError());
	out->append ((const char*)block, outLen);
	state = CRYPT_S_FINALIZED;
	return *out;
}

// Decryption

Decryption::Decryption (const char *cipher_name) : state(CRYPT_S_CREATED), out(&defaultOut) {
	this->cipher = getCipher(cipher_name);
	this->ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		throw std::runtime_error ("Failed to create decryption context: "+ getCryptError());
	out->reserve(EVP_CIPHER_block_size(cipher) * 4 + 1); // some reserve
}

Decryption::Decryption (Decryption &&o) : cipher(o.cipher), ctx(o.ctx),
	state(o.state), defaultOut(std::move(o.defaultOut)), out(o.out)
{
	o.state = CRYPT_S_UNINITIALIZED;
	o.ctx = nullptr;
}

Decryption::~Decryption () {
	// Can only be null if this object was moved from
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
}

void Decryption::setOutputBuffer (std::string *pOut) {
	if (!pOut)
		this->out = &defaultOut;
	else
		this->out = pOut;
}

void Decryption::init (const std::string &key, const std::string &iv, const std::string &tag) {
	if (state != CRYPT_S_CREATED && state != CRYPT_S_FINALIZED)
		throw std::logic_error ("Decryption::init: Invalid state");
	validate_key_and_iv(key, iv, cipher);
	if (tag.size() != GCM_TAG_LENGTH)
		throw std::runtime_error ("Decryption: Unexpected tag length given: "+ getCryptError());
	out->clear();
	if (EVP_DecryptInit(ctx, cipher, nullptr, nullptr) != 1)
		throw std::runtime_error ("Failed to initialize decryption cipher: "+ getCryptError());
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL) != 1)
		throw std::runtime_error ("Failed to set cipher iv length: "+ getCryptError());
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LENGTH, (void*)tag.c_str()) != 1)
		throw std::runtime_error ("Failed to set decryption tag: "+ getCryptError());
	if (EVP_DecryptInit(ctx, nullptr, (const unsigned char*)key.c_str(),
		(const unsigned char*)iv.c_str()) != 1) {
		throw std::runtime_error ("Failed to initialize decryption: "+ getCryptError());
	}
	state = CRYPT_S_INITIALIZED;
}

void Decryption::feed (const void *mem, int length) {
	if (state != CRYPT_S_INITIALIZED && state != CRYPT_S_UPDATE)
		throw std::logic_error ("Decryption::feed: Invalid state");
	int outLen = length * 2;
	unsigned char block[outLen];
	if (EVP_DecryptUpdate(ctx, block, &outLen, (unsigned char*)mem, length) != 1)
		throw std::runtime_error ("Failed to decrypt data: "+ getCryptError());
	out->append ((const char*)block, outLen);
	state = CRYPT_S_UPDATE;
}

const std::string &Decryption::finalize () {
	if (state != CRYPT_S_UPDATE)
		throw std::logic_error ("Decryption::finalize: Invalid state");
	int outLen = EVP_CIPHER_block_size(EVP_CIPHER_CTX_cipher(ctx)) + 1;
	unsigned char block[outLen];
	if (EVP_DecryptFinal_ex(ctx, block, &outLen) != 1)
		throw std::runtime_error ("Failed to finalize data decryption: "+ getCryptError());
	out->append ((const char*)block, outLen);
	state = CRYPT_S_FINALIZED;
	return *out;
}

// 

std::string getCryptError () {
	int err_code = ERR_get_error();
	return ERR_error_string(err_code, nullptr);
}

int IvSizeForCipher (const char *cipher_name) {
	const EVP_CIPHER *cipher = getCipher(cipher_name);
	return EVP_CIPHER_iv_length(cipher);
}

int KeySizeForCipher (const char *cipher_name) {
	const EVP_CIPHER *cipher = getCipher(cipher_name);
	return EVP_CIPHER_key_length(cipher);
}

void InitCryptLibrary () {
	//OpenSSL_add_all_ciphers();
	EVP_add_cipher(EVP_aes_256_gcm());
	EVP_add_cipher(EVP_aes_256_ctr());
	EVP_add_cipher(EVP_aes_256_cbc_hmac_sha1());
	EVP_add_digest(EVP_md5());
	EVP_add_digest(EVP_sha1());
	EVP_add_digest(EVP_sha256());
	ERR_load_crypto_strings();
}

void uc2sc (char *destStr, const unsigned char *sourceStr, int len) {
	static const char hexits[] = "0123456789abcdef";
	for (int i = 0; i < len; ++i) {
		destStr[i * 2] = hexits[sourceStr[i] >> 4];
		destStr[i * 2 + 1] = hexits[sourceStr[i] &  0x0F];
	}
}

void generateHash (const char *in, size_t length, std::string *out, const char *algoName) {
	assert (in);
	assert (out);
	const EVP_MD *algo = getHashAlgo(algoName);
	unsigned char temp_buf[EVP_MAX_MD_SIZE];
	EVP_MD_CTX ctx;
	EVP_MD_CTX_init(&ctx);
	int r = EVP_DigestInit_ex(&ctx, algo, nullptr);
	if (r != 1)
		throw std::runtime_error ("Cannot initialize hash structure: "+ getCryptError());
	r = EVP_DigestUpdate(&ctx, in, length);
	if (r != 1)
		throw std::runtime_error ("Error during hash computation: "+ getCryptError());
	unsigned int s = EVP_MAX_MD_SIZE;
	r = EVP_DigestFinal_ex(&ctx, temp_buf, &s);
	if (r != 1)
		throw std::runtime_error ("Failed to compute hash: "+ getCryptError());
	out->resize(s * 2);
	uc2sc(&(*out)[0], temp_buf, s);
}

void generateRandomBytes (int length, void *out) {
	RAND_pseudo_bytes((unsigned char*)out, length);
}

void generateRandomString (int length, std::string *out) {
	out->resize(length);
	RAND_pseudo_bytes((unsigned char*)&(*out)[0], length);
}

std::string base64Encode (const void *mem, int length) {
	BIO *bio, *b64;
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	BIO_push(b64, bio);
	BIO_write(b64, mem, length);
	(void)BIO_flush(b64);
	char *dataPtr;
	long outSize = BIO_get_mem_data(bio, &dataPtr);
	std::string out (dataPtr, std::max(0L, outSize-1));
	BIO_free_all(b64);
	return std::move(out);
}

std::string base64Decode (const void *mem, int length) {
	// TODO
	throw std::logic_error ("base64Decode not implemented");
}

}
}
