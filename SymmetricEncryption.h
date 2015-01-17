#pragma once

#include <memory>
#include <vector>
#include <string>

struct evp_cipher_ctx_st;
struct evp_cipher_st;

namespace NetCrypt {
namespace Crypt {

void InitCryptLibrary ();

extern const char *DEFAULT_CIPHER;
extern const char *DEFAULT_HASH_ALGORITHM;

const int GCM_TAG_LENGTH = 16;

enum InternalCryptState : char;

class Encryption
{
public:
	Encryption (const char *cipher);
	Encryption (Encryption &&o);
	~Encryption ();
	
	void init (const std::string &key, const std::string &iv);
	
	void feed (const void *mem, int length);
	
	inline void feed (const std::string &data) {
		feed (data.c_str(), data.size());
	}
	
	void setOutputBuffer (std::string *out);
	
	const std::string &finalize ();
	
	inline std::string tagString () const { return std::string(ctag, GCM_TAG_LENGTH); }
	
	inline const char *tag () const { return ctag; }
private:
	const evp_cipher_st *cipher;
	evp_cipher_ctx_st *ctx;
	char ctag[GCM_TAG_LENGTH];
	InternalCryptState state;
	std::string defaultOut;
	std::string *out;
	
	Encryption (const Encryption&) = delete;
	Encryption &operator= (const Encryption &) = delete;
};

class Decryption
{
public:
	Decryption (const char *cipher);
	Decryption (Decryption &&o);
	~Decryption ();
	
	void init (const std::string &key, const std::string &iv, const std::string &tag);
	
	void feed (const void *mem, int length);
	
	inline void feed (const std::string &data) {
		feed (data.c_str(), data.size());
	}
	
	void setOutputBuffer (std::string *out);
	
	const std::string &finalize ();
private:
	const evp_cipher_st *cipher;
	evp_cipher_ctx_st *ctx;
	InternalCryptState state;
	std::string defaultOut;
	std::string *out;
	
	Decryption (const Decryption&) = delete;
	Decryption &operator= (const Decryption &) = delete;
};

std::string getCryptError ();

int IvSizeForCipher (const char *cipher = 0);
int KeySizeForCipher (const char *cipher = 0);

void generateRandomBytes (int length, void *out);

void generateRandomString (int length, std::string *out);

void uc2sc (char *destStr, const unsigned char *sourceStr, int len);

void generateHash (const char *in, size_t length, std::string *out, const char *algo = DEFAULT_HASH_ALGORITHM);

void keyDerivation (const char *pass, int passlen, const char *salt, int saltlen,
	uint32_t keyDerivationCount, const char *cipher, unsigned char *out, int keylen);

inline void generateHash (const std::string &in, std::string *out, const char *algo = DEFAULT_HASH_ALGORITHM) {
	generateHash (in.c_str(), in.size(), out, algo);
}

inline std::string generateRandomString (int length) {
	std::string s;
	generateRandomString (length, &s);
	return std::move(s);
}

std::string base64Encode (const void *mem, int length);
std::string base64Decode (const void *mem, int length);

inline std::string base64Encode (const std::string &data) {
	return base64Encode(data.c_str(), data.size());
}

}
}
