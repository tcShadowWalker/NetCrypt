/*
    Copyright (C) 2015 Jan-Philip Stecker.
    This file is part of NetCrypt.

    NetCrypt is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    NetCrypt is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with NetCrypt.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "NetCrypt.h"
#include "Progress.h"
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
namespace Crypt { void InitCryptLibrary (); }

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

void receiveData (const ProgOpts &pOpt, const DataStream &dStream, int dataSocket);
void sendData (const ProgOpts &pOpt, const DataStream &dStream, int dataSocket);

void receiveUnencryptedData (const ProgOpts &pOpt, const DataStream &dStream, int dataSocket);
void sendUnencryptedData (const ProgOpts &pOpt, const DataStream &dStream, int dataSocket);

void sendOrReceive (const ProgOpts &progOpt, const DataStream &dStream, int dataSocket) {
	if (progOpt.op == OP_READ) {
		if (progOpt.useEncryption)
			receiveData(progOpt, dStream, dataSocket);
		else
			receiveUnencryptedData(progOpt, dStream, dataSocket);
	} else {
		if (progOpt.useEncryption)
			sendData(progOpt, dStream, dataSocket);
		else
			sendUnencryptedData(progOpt, dStream, dataSocket);
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
					if (progOpt.showProgress) ProgressTracker::clear();
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
