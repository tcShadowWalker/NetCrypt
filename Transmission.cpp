#include "Transmission.h"
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdexcept>

namespace NetCrypt {

Transmission::Transmission (size_t pBSize) : blockSize (pBSize), dataSocket(-1) { }

bool Transmission::secure () const { return !passphrase.empty(); }

void Transmission::showProgress (bool s) {
	doShowProgress = s;
}

void Transmission::writeDataToFile (std::ostream &outStream, const char *data, size_t length) {
	outStream.write(data, length);
}

size_t Transmission::fetchDataFromFile (std::istream &inStream, char *data, size_t length) {
	inStream.read(data, length);
	ssize_t r = inStream.gcount();
	return r;
}

void Transmission::writeDataToSocket (const char *data, size_t length) {
	size_t sentPkgBytes = 0;
	while (sentPkgBytes < length) {
		ssize_t w = write(dataSocket, &data[sentPkgBytes], length - sentPkgBytes);
		if (w <= 0)
			throw std::runtime_error ("Write error. " + std::string((errno != 0) ? strerror(errno) : ""));
		sentPkgBytes += w;
	}
}

void Transmission::receive (int pDataSocket, std::ostream &outStream) {
	this->dataSocket = pDataSocket;
	if (secure())
		receive_Secure(outStream);
	else
		receive_Insecure(outStream);
}

void Transmission::send (int pDataSocket, std::istream &inStream, size_t totalSize) {
	this->dataSocket = pDataSocket;
	if (secure())
		send_Secure(inStream, totalSize);
	else
		send_Insecure(inStream, totalSize);
}

void Transmission::setPassphrase (const std::string pPassphrase, uint32_t pKeyIterationCount) {
	if (pPassphrase.empty())
		throw std::logic_error ("Cannot set an empty passphrase");
	this->passphrase = std::move(pPassphrase);
	this->keyIterationCount = pKeyIterationCount;
}

void openNetDevice (NetworkOpType netOp, const std::string &hostname, uint16_t port, int *dataSocket) {
	std::array<char,50> addr_ascii;
	if (netOp == NET_CONNECT) {
		struct addrinfo hint;
		memset(&hint, 0, sizeof(hint));
		hint.ai_socktype = SOCK_STREAM;
		struct addrinfo *results = 0;
		int r = getaddrinfo(hostname.c_str(), std::to_string(port).c_str(), &hint, &results);
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
	} else if (netOp == NET_LISTEN) {
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
		addr.sin6_port = htons(port);
		if (bind(*dataSocket, (const sockaddr*)&addr, sizeof(addr)) != 0)
			throw std::runtime_error ("Failed to bind socket: " + std::string(strerror(errno)));
		if (listen(*dataSocket, 1) != 0)
			throw std::runtime_error ("Failed to listen on socket: " + std::string(strerror(errno)));
	}
	assert (*dataSocket != -1);
}

}
