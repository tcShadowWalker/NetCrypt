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
#include "Transmission.h"
#include "CmdlineOptions.h"
#include "Progress.h"
#include <iostream>
#include <string.h>
#include <stdexcept>
#include <array>
#include <signal.h>
#include <unistd.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netdb.h>

namespace NetCrypt {
namespace Crypt { void InitCryptLibrary (); }

int DebugEnabled = 0;

bool evaluateOptions (int argc, char **argv, ProgOpts *opt);

void openInOutStream (DataStream *dstream, ProgOpts *opt);

void sendOrReceive (const ProgOpts &progOpt, const DataStream &dStream, int dataSocket) {
	Transmission t (progOpt.blockSize);
	if (progOpt.useEncryption) {
		t.setPassphrase(progOpt.passphrase, progOpt.keyIterationCount);
		t.setPreferredCipher(progOpt.preferredCipher);
	}
	t.showProgress (progOpt.showProgress);
	if (progOpt.op == OP_READ) {
		t.receive(dataSocket, *dStream.out);
	} else {
		t.send(dataSocket, *dStream.in, dStream.totalSize);
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
		uint16_t port = (progOpt.netOp == NET_LISTEN) ? progOpt.listen_port : progOpt.target_port;
		openNetDevice (progOpt.netOp, progOpt.target_host, port, &serverSock);
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
