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
#include <stdexcept>
#include <iostream>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <vector>
#include <arpa/inet.h>

namespace NetCrypt {

void writeDataToFile (const DataStream &dStream, const char *data, size_t length);
size_t fetchDataFromFile (const DataStream &dStream, char *data, size_t length);

void receiveUnencryptedData (const ProgOpts &pOpt, const DataStream &dStream, int dataSocket) {
	assert (dataSocket != -1);
	assert (pOpt.op == OP_READ);
	assert (dStream.out != nullptr);
	std::vector<char> buffer ( std::min<size_t>(pOpt.blockSize, SecureMagicCookie.size()) );
	ProgressTracker tracker (0);
	{
		ssize_t s = recv(dataSocket, &buffer[0], SecureMagicCookie.size(), MSG_PEEK);
		if (s == SecureMagicCookie.size() && strncmp (&buffer[0],
			SecureMagicCookie.begin(), SecureMagicCookie.size()) == 0)
		{
			throw std::runtime_error ("This looks like an encrypted transmission. "
				"You should give the correct passphrase and omit --no-encryption.");
		}
	}
	while (true) {
		ssize_t s = read (dataSocket, &buffer[0], buffer.size());
		if (s < 0)
			throw std::runtime_error ("Read error: " +
				std::string((errno != 0) ? strerror(errno) : ""));
		else if (s == 0)
			break;
		if (DebugEnabled >= 3)
			std::cerr << "Read payload: " << s << "\n";
		tracker.add((size_t)s);
		if (pOpt.showProgress)
			tracker.printProgress();
		writeDataToFile (dStream, buffer.data(), buffer.size());
	}
	if (pOpt.showProgress)
		std::cerr << "\n";
	Debug ("Total bytes read: " + std::to_string(tracker.totalSize()));
}

void sendUnencryptedData (const ProgOpts &pOpt, const DataStream &dStream, int dataSocket) {
	assert (pOpt.op == OP_WRITE);
	assert (dataSocket != -1);
	assert (dStream.in != nullptr);
	std::vector<char> buffer (pOpt.blockSize);
	ProgressTracker tracker (dStream.totalSize);
	while (true) {
		const size_t r = fetchDataFromFile(dStream, buffer.data(), buffer.size());
		if (r == 0)
			break;
		if (DebugEnabled >= 3)
			std::cerr << "Sent: " << r << "\n";
		ssize_t w = write(dataSocket, &buffer[0], buffer.size());
		if (w <= 0)
			throw std::runtime_error ("Write error. " + std::string((errno != 0) ? strerror(errno) : ""));
		tracker.add((size_t)w);
		if (pOpt.showProgress)
			tracker.printProgress();
	}
	if (pOpt.showProgress)
		std::cerr << "\n";
	Debug ("Total bytes sent: " + std::to_string(tracker.totalSize()));
}

}
