#include "NetCrypt.h"
#include "SymmetricEncryption.h"
#include <iostream>
#include <vector>
#include <string.h>
#include <netdb.h>
#include <stdexcept>
#include <array>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#include <assert.h>

namespace NetCrypt {

int DebugEnabled = 0;

bool evaluateOptions (int argc, char **argv, ProgOpts *opt);

void openInOutStream (DataStream *dstream, ProgOpts *opt);

void openNetDevice (const ProgOpts &pOpt, DataStream &dStream, int *dataSocket) {
	std::array<char,50> addr_ascii;
	if (pOpt.netOp == NET_CONNECT) {
		struct addrinfo hint;
		memset(&hint, 0, sizeof(hint));
		hint.ai_socktype = SOCK_STREAM;
		struct addrinfo *results = 0;
		int r = getaddrinfo(pOpt.target_host.c_str(), std::to_string(pOpt.target_port).c_str(), &hint, &results);
		if (r != 0)
			throw std::runtime_error (gai_strerror(r));
		for (struct addrinfo *res = results; res; res = res->ai_next) {
			*dataSocket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
			if (*dataSocket < 0)
				continue;
			getnameinfo((const sockaddr*)res->ai_addr, res->ai_addrlen,
						addr_ascii.data(), addr_ascii.size() - 1, 0, 0, 0);
			Debug(std::string("Connecting to ") + addr_ascii.data());
			if (connect(*dataSocket, res->ai_addr, res->ai_addrlen) == 0) {
				break;
			}
			close(*dataSocket);
			*dataSocket = -1;
		}
		freeaddrinfo(results);
		if (*dataSocket == -1)
			throw std::runtime_error ("Failed to establish connection: " + std::string(strerror(errno)));
	} else if (pOpt.netOp == NET_LISTEN) {
		*dataSocket = socket(AF_INET6, SOCK_STREAM, 0);
		if (*dataSocket < 0)
			throw std::runtime_error ("Failed to open socket: " + std::string(strerror(errno)));
		int reuseaddr = 1;
		if (setsockopt(*dataSocket, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) != 0)
			throw std::runtime_error ("Failed to set socket options: " + std::string(strerror(errno)));
		sockaddr_in6 addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin6_addr = IN6ADDR_ANY_INIT;
		addr.sin6_family = AF_INET6;
		addr.sin6_port = htons(pOpt.listen_port);
		if (bind(*dataSocket, (const sockaddr*)&addr, sizeof(addr)) != 0)
			throw std::runtime_error ("Failed to bind socket: " + std::string(strerror(errno)));
		if (listen(*dataSocket, 1) != 0)
			throw std::runtime_error ("Failed to listen on socket: " + std::string(strerror(errno)));
	}
	assert (*dataSocket != -1);
}

void writeDataToFile (DataStream &dStream, const char *data, size_t length) {
	dStream.out->write(data, length);
}

size_t fetchDataFromFile (DataStream &dStream, char *data, size_t length) {
	dStream.in->read(data, length);
	ssize_t r = dStream.in->gcount();
	return r;
}

struct TransmissionHeader {
	uint32_t keyIterationCount;
	uint16_t version = 1;
	uint8_t saltLength;
	uint8_t _padding1_ = 0;
	uint64_t totalSize;
	char salt[30];
	char cipherName[30]; // Null-terminated cipher name
};

std::string printableString (const std::string &s) {
	std::string n (s.size() * 2, '\0');
	Crypt::uc2sc(&n[0], (const unsigned char*)s.c_str(), s.size());
	return std::move(n);
}

void printDebugCryptoParameters (const TransmissionHeader &tInfo, const std::string &pass) {
	std::cerr << "Salt: '" << printableString(std::string(tInfo.salt, tInfo.saltLength)) << "'\n";
	std::cerr << "Key: '" << printableString(pass) << "'\n";
	std::cerr << "Key iteration count: " << tInfo.keyIterationCount << "\n";
	std::cerr << "Total byte size: " << tInfo.totalSize << "\n";
}

void receiveData (const ProgOpts &pOpt, DataStream &dStream, int dataSocket) {
	assert (dataSocket != -1);
	assert (pOpt.op == OP_READ);
	assert (dStream.out != nullptr);
	size_t totalByteCount = 0;
	TransmissionHeader tranInfo;
	if (read (dataSocket, &tranInfo, sizeof(tranInfo)) != sizeof(tranInfo))
		throw std::runtime_error ("Read init error: " + std::string(strerror(errno)));
	const std::string usedCipher (tranInfo.cipherName,
							strnlen(tranInfo.cipherName, sizeof(tranInfo.cipherName)));
	Debug ("Using cipher " + usedCipher);
	std::string realPassphrase (Crypt::KeySizeForCipher(usedCipher.c_str()), '\0');
	Crypt::keyDerivation(pOpt.passphrase.c_str(), pOpt.passphrase.size(),
						tranInfo.salt, tranInfo.saltLength, pOpt.keyIterationCount,
						0, (unsigned char*)&realPassphrase[0], realPassphrase.size());
	const size_t ivLen = Crypt::IvSizeForCipher(usedCipher.c_str()),
				tagLen = Crypt::GCM_TAG_LENGTH;
	Debug("IV length: " + std::to_string(ivLen) + ", tag length: " + std::to_string(tagLen));
	if (DebugEnabled >= 2)
		printDebugCryptoParameters (tranInfo, realPassphrase);
	const size_t HeaderSize = ivLen + tagLen + sizeof(uint32_t);
	uint32_t blockSize = pOpt.blockSize;
	std::vector<char> buffer ( blockSize + HeaderSize );
	Crypt::Decryption dec (usedCipher.c_str());
	std::string decryptedBlock;
	dec.setOutputBuffer(&decryptedBlock);
	while (true) {
		const ssize_t s = read (dataSocket, buffer.data(), buffer.size());
		if (s == 0)
			break;
		else if (s < 0)
			throw std::runtime_error ("Read error: " + std::string(strerror(errno)));
		if (DebugEnabled >= 3) {
			std::cerr << "IV: " << printableString(std::string(buffer.data(), ivLen)) << "\n";
			std::cerr << "Tag: " << printableString(std::string(buffer.data() + ivLen, tagLen)) << "\n";
		}
		dec.init (realPassphrase, std::string(buffer.data(), ivLen),
					std::string(buffer.data() + ivLen, tagLen));
		memcpy (&blockSize, buffer.data() + ivLen + tagLen, sizeof(blockSize));
		if (blockSize > buffer.size() - HeaderSize)
			throw std::runtime_error ("Received block size too large");
		dec.feed(&buffer[HeaderSize], blockSize);
		if (DebugEnabled >= 3) {
			std::string hash;
			Crypt::generateHash(buffer.data(), buffer.size(), &hash);
			std::cerr << "Read: " << blockSize << " (Digest: " << hash << ")\n";
		}
		try {
			dec.finalize();
		} catch (const std::exception &e) {
			throw std::runtime_error ("Decryption failed. Probably the given "
				"passphrase does not match the one used for encryption");
		}
		totalByteCount += s;
		writeDataToFile (dStream, decryptedBlock.data(), decryptedBlock.size());
	}
	Debug ("Total bytes read: " + std::to_string(totalByteCount));
}

void sendData (const ProgOpts &pOpt, DataStream &dStream, int dataSocket) {
	assert (pOpt.op == OP_WRITE);
	assert (dataSocket != -1);
	assert (dStream.in != nullptr);
	size_t totalByteCount = 0;
	const std::string cipher = pOpt.preferedCipher;
	const size_t ivLen = Crypt::IvSizeForCipher(cipher.c_str()),
				tagLen = Crypt::GCM_TAG_LENGTH;
	std::string realPassphrase (Crypt::KeySizeForCipher(cipher.c_str()), '0');
	std::vector<char> buffer (pOpt.blockSize);
	TransmissionHeader tranInfo;
	tranInfo.saltLength = sizeof(tranInfo.salt);
	Crypt::generateRandomBytes(tranInfo.saltLength, tranInfo.salt);
	Crypt::keyDerivation(pOpt.passphrase.c_str(), pOpt.passphrase.size(),
						tranInfo.salt, tranInfo.saltLength, pOpt.keyIterationCount,
						0, (unsigned char*)&realPassphrase[0], realPassphrase.size());
	tranInfo.keyIterationCount = pOpt.keyIterationCount;
	tranInfo.totalSize = dStream.totalSize;
	strncpy (tranInfo.cipherName, cipher.c_str(), sizeof(tranInfo.cipherName));
	if (DebugEnabled >= 2)
		printDebugCryptoParameters (tranInfo, realPassphrase);
	if (write (dataSocket, &tranInfo, sizeof(tranInfo)) != sizeof(tranInfo))
		throw std::runtime_error ("Write init error: " + std::string(strerror(errno)));
	Crypt::Encryption enc (cipher.c_str());
	std::string outDataBlack;
	enc.setOutputBuffer(&outDataBlack);
	char iv[ivLen + 1];
	const size_t HeaderSize = ivLen + tagLen + sizeof(uint32_t);
	while (true) {
		const size_t r = fetchDataFromFile(dStream, buffer.data(), buffer.size());
		if (r == 0)
			break;
		Crypt::generateRandomBytes(ivLen, iv);
		enc.init (realPassphrase, std::string(iv, ivLen));
		outDataBlack.resize(HeaderSize);
		enc.feed (buffer.data(), r);
		enc.finalize();
		if (DebugEnabled >= 3) {
			std::cerr << "IV: " << printableString(std::string(iv, ivLen)) << "\n";
			std::cerr << "Tag: " << printableString(std::string(enc.tag(), tagLen)) << "\n";
		}
		char *header = &outDataBlack[0];
		const uint32_t bsize = outDataBlack.size() - HeaderSize;
		memcpy (&header[           0], iv, ivLen);
		memcpy (&header[       ivLen], enc.tag(), tagLen);
		memcpy (&header[ivLen+tagLen], &bsize, sizeof(bsize));
		ssize_t w = write(dataSocket, outDataBlack.data(), outDataBlack.size());
		if (DebugEnabled >= 3) {
			std::string hash;
			Crypt::generateHash(outDataBlack, &hash);
			std::cerr << "Sent: " << r << " (Digest: " << hash << ")\n";
		}
		if (w != outDataBlack.size())
			throw std::runtime_error ("Write error. " + std::string((errno != 0) ? strerror(errno) : ""));
		totalByteCount += r;
	}
	Debug ("Total bytes sent: " + std::to_string(totalByteCount));
}

void sendOrReceive (const ProgOpts &progOpt, DataStream &dStream, int dataSocket) {
	if (progOpt.op == OP_READ) {
		receiveData(progOpt, dStream, dataSocket);
	} else {
		sendData(progOpt, dStream, dataSocket);
	}
}

}

int main (int argc, char **argv) {
	using namespace NetCrypt;
	ProgOpts progOpt;
	DataStream dStream;
	try {
		if (!evaluateOptions (argc, argv, &progOpt))
			return 1;
		Crypt::InitCryptLibrary();
		assert (progOpt.netOp != NET_NONE);
		Debug(std::string("Network mode: ") + ( (progOpt.netOp == NET_LISTEN) ? "Listen" : "Connect" ));
		openInOutStream (&dStream, &progOpt);
		assert (progOpt.op != OP_NONE);
		Debug(std::string("Network operation: ") + ( (progOpt.op == OP_READ) ? "Read" : "Write" ));
	} catch (const std::exception &e) {
		std::cerr << "Error parsing command line options:\n" << e.what() << "\n";
		return 1;
	}
	signal(SIGPIPE, SIG_IGN);
	int serverSock;
	try {
		openNetDevice (progOpt, dStream, &serverSock);
	} catch (const std::exception &e) {
		std::cerr << "Networking error: " << e.what() << "\n";
		return 1;
	}
	try {
		std::array<char, 50> addr_ascii;
		if (progOpt.netOp == NET_LISTEN) {
			struct sockaddr_storage client_addr;
			do {
				socklen_t addr_len = sizeof(client_addr);
				int dataSocket = accept (serverSock, (sockaddr*)&client_addr, &addr_len);
				try {
					if (dataSocket == -1)
						throw std::runtime_error ("Failed to accept connection: " + std::string(strerror(errno)));
					getnameinfo((const sockaddr*)&client_addr, addr_len,
									addr_ascii.data(), addr_ascii.size() - 1, 0, 0, 0);
					Debug(std::string("Connection from ") + addr_ascii.data());
					sendOrReceive (progOpt, dStream, dataSocket);
				} catch (const std::exception &e) {
					std::cerr << "Connection error: " << e.what() << "\n";
				}
				if (dataSocket != -1)
					close(dataSocket);
				if (!progOpt.acceptOnce) {
					dStream = DataStream();
					openInOutStream (&dStream, &progOpt);
				}
			} while (progOpt.acceptOnce == false);
		} else if (progOpt.netOp == NET_CONNECT) {
			sendOrReceive (progOpt, dStream, serverSock);
		}
		close(serverSock);
	} catch (const std::exception &e) {
		std::cerr << "Operation error: " << e.what() << "\n";
		return 1;
	}
	return 0;
}
