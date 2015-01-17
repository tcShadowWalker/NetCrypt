#include "JpsNet.h"
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

namespace JpsNet {

bool DebugEnabled = false;

bool evaluateOptions (int argc, char **argv, ProgOpts *opt);

void determineInOut (DataStream *dstream, ProgOpts *opt);

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
			dStream.socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
			if (dStream.socket < 0)
				continue;
			getnameinfo((const sockaddr*)res->ai_addr, res->ai_addrlen,
						addr_ascii.data(), addr_ascii.size() - 1, 0, 0, 0);
			Debug(std::string("Connecting to ") + addr_ascii.data());
			if (connect(dStream.socket, res->ai_addr, res->ai_addrlen) == 0) {
				break;
			}
			close(dStream.socket);
			dStream.socket = -1;
		}
		freeaddrinfo(results);
		if (dStream.socket == -1)
			throw std::runtime_error ("Failed to establish connection: " + std::string(strerror(errno)));
		*dataSocket = dStream.socket;
	} else if (pOpt.netOp == NET_LISTEN) {
		dStream.socket = socket(AF_INET6, SOCK_STREAM, 0);
		if (dStream.socket < 0)
			throw std::runtime_error ("Failed to open socket: " + std::string(strerror(errno)));
		int reuseaddr = 1;
		if (setsockopt(dStream.socket, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) != 0)
			throw std::runtime_error ("Failed to set socket options: " + std::string(strerror(errno)));
		sockaddr_in6 addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin6_addr = IN6ADDR_ANY_INIT;
		addr.sin6_family = AF_INET6;
		addr.sin6_port = htons(pOpt.listen_port);
		if (bind(dStream.socket, (const sockaddr*)&addr, sizeof(addr)) != 0)
			throw std::runtime_error ("Failed to bind socket: " + std::string(strerror(errno)));
		if (listen(dStream.socket, 1) != 0)
			throw std::runtime_error ("Failed to listen on socket: " + std::string(strerror(errno)));
		struct sockaddr_storage client_addr;
		socklen_t addr_len = sizeof(client_addr);
		*dataSocket = accept (dStream.socket, (sockaddr*)&client_addr, &addr_len);
		if (*dataSocket == -1)
			throw std::runtime_error ("Failed to accept connection: " + std::string(strerror(errno)));
		getnameinfo((const sockaddr*)&client_addr, addr_len,
						addr_ascii.data(), addr_ascii.size() - 1, 0, 0, 0);
		Debug(std::string("Connection from ") + addr_ascii.data());
	}
	assert (dStream.socket != -1);
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
	uint16_t version;
	uint8_t saltLength;
	uint8_t _padding1_;
	char salt[30];
	char cipherName[30]; // Null-terminated cipher name
};

std::string printableString (const std::string &s) {
	std::string n (s.size() * 2, '\0');
	Crypt::uc2sc(&n[0], (const unsigned char*)s.c_str(), s.size());
	return std::move(n);
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
	uint32_t blockSize = pOpt.blockSize;
	std::vector<char> buffer ( blockSize + sizeof(blockSize) + ivLen + tagLen );
	Crypt::Decryption dec (usedCipher.c_str());
	std::string decryptedBlock;
	dec.setOutputBuffer(&decryptedBlock);
	while (true) {
		const ssize_t s = read (dataSocket, buffer.data(), buffer.size());
		if (s == 0)
			break;
		else if (s < 0)
			throw std::runtime_error ("Read error: " + std::string(strerror(errno)));
		dec.init (realPassphrase, std::string(buffer.data(), ivLen),
					std::string(buffer.data() + ivLen, tagLen));
		memcpy (&blockSize, buffer.data() + ivLen + tagLen, sizeof(blockSize));
		if (blockSize > buffer.size())
			throw std::runtime_error ("Received block size too large");
		dec.feed(buffer.data() + ivLen + tagLen + sizeof(blockSize), blockSize);
		try {
			dec.finalize();
		} catch (const std::exception &e) {
			if (DebugEnabled)
				Debug(e.what());
			throw std::runtime_error ("Decryption failed. Probably the given "
				"passphrase does not match the one used for encryption");
		}
		Debug("Read: " + std::to_string(decryptedBlock.size()));
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
	strncpy (tranInfo.cipherName, cipher.c_str(), sizeof(tranInfo.cipherName));
	if (write (dataSocket, &tranInfo, sizeof(tranInfo)) != sizeof(tranInfo))
		throw std::runtime_error ("Write init error: " + std::string(strerror(errno)));
	Crypt::Encryption enc (cipher.c_str());
	std::string encryptedBlock;
	enc.setOutputBuffer(&encryptedBlock);
	char iv[ivLen + 1];
	while (true) {
		const size_t r = fetchDataFromFile(dStream, buffer.data(), buffer.size());
		if (r == 0)
			break;
		Crypt::generateRandomBytes(ivLen, iv);
		enc.init (realPassphrase, std::string(iv, ivLen));
		enc.feed (buffer.data(), r);
		enc.finalize();
		const uint32_t encBlockSize = encryptedBlock.size();
		iovec iov[4] = {
			{iv, ivLen},
			{(void*)enc.tag(), tagLen},
			{(void*)&encBlockSize, sizeof(encBlockSize)},
			{(void*)encryptedBlock.data(), encryptedBlock.size()},
		};
		const size_t expected = encryptedBlock.size() + ivLen + tagLen + sizeof(encBlockSize);
		ssize_t w = writev(dataSocket, iov, 4);
		Debug("Sent: " + std::to_string(r));
		if (w != expected)
			throw std::runtime_error ("Write error: " + std::string(strerror(errno)));
		totalByteCount += r;
	}
	Debug ("Total bytes sent: " + std::to_string(totalByteCount));
}

}

int main (int argc, char **argv) {
	using namespace JpsNet;
	ProgOpts progOpt;
	DataStream dStream;
	try {
		if (!evaluateOptions (argc, argv, &progOpt))
			return 1;
		Crypt::InitCryptLibrary();
		assert (progOpt.netOp != NET_NONE);
		Debug(std::string("Network mode: ") + ( (progOpt.netOp == NET_LISTEN) ? "Listen" : "Connect" ));
		determineInOut (&dStream, &progOpt);
		assert (progOpt.op != OP_NONE);
		Debug(std::string("Network operation: ") + ( (progOpt.op == OP_READ) ? "Read" : "Write" ));
	} catch (const std::exception &e) {
		std::cerr << "Error parsing command line options:\n" << e.what() << "\n";
		return 1;
	}
	signal(SIGPIPE, SIG_IGN);
	int dataSocket;
	try {
		openNetDevice (progOpt, dStream, &dataSocket);
	} catch (const std::exception &e) {
		std::cerr << "Networking error: " << e.what() << "\n";
		return 1;
	}
	try {
		if (progOpt.op == OP_READ)
			receiveData (progOpt, dStream, dataSocket);
		else
			sendData (progOpt, dStream, dataSocket);
		close(dStream.socket);
	} catch (const std::exception &e) {
		std::cerr << "Operation error: " << e.what() << "\n";
		return 1;
	}
	return (dStream.transmissionOk == true) ? 0 : 1;
}
