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
#include "Transmission.h"
#include "Progress.h"
#include <stdexcept>
#include <iostream>
#include <unistd.h>
#include <string.h>
#include <vector>
#include <arpa/inet.h>

namespace NetCrypt {

static void compareMagicCookie (int dataSocket) {
	char buffer[SecureMagicCookie.size() + 1];
	ssize_t s = recv(dataSocket, &buffer[0], SecureMagicCookie.size(), MSG_PEEK);
	if ((size_t)s == SecureMagicCookie.size() && strncmp (&buffer[0],
		SecureMagicCookie.begin(), SecureMagicCookie.size()) == 0)
	{
		throw std::runtime_error ("This looks like an encrypted transmission. "
			"You should give the correct passphrase and enable encryption.");
	}
}

void Transmission::receive_Insecure (std::ostream &outStream) {
	std::vector<char> buffer ( blockSize );
	ProgressTracker tracker (0);
	compareMagicCookie (dataSocket);
	while (true) {
		ssize_t s = read (dataSocket, &buffer[0], buffer.size());
		if (s < 0)
			throw std::runtime_error ("Read error: " +
				std::string((errno != 0) ? strerror(errno) : ""));
		else if (s == 0)
			break;
		if (DebugEnabled >= 3) {
			if (doShowProgress)
				ProgressTracker::clear();
			std::cerr << "Read payload: " << s << "\n";
		}
		tracker.add((size_t)s);
		if (doShowProgress)
			tracker.printProgress();
		writeDataToFile (outStream, buffer.data(), s);
	}
	if (doShowProgress)
		std::cerr << "\n";
	Debug ("Total bytes read: " + std::to_string(tracker.totalSize()));
}

void Transmission::send_Insecure (std::istream &inStream, size_t totalSize) {
	std::vector<char> buffer (blockSize);
	ProgressTracker tracker (totalSize);
	while (true) {
		const size_t r = fetchDataFromFile(inStream, buffer.data(), buffer.size());
		if (r == 0)
			break;
		if (DebugEnabled >= 3)
			std::cerr << "Sent: " << r << "\n";
		writeDataToSocket(&buffer[0], r);
	}
	if (doShowProgress)
		std::cerr << "\n";
	Debug ("Total bytes sent: " + std::to_string(tracker.totalSize()));
}

}
