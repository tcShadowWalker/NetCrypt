#pragma once
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

namespace NetCrypt {

void openNetDevice (NetworkOpType netOp, const std::string &hostname, uint16_t port, int *dataSocket);

class Transmission
{
public:
	Transmission (size_t blockSize);
	
	void showProgress (bool s);
	
	void setPreferredCipher (const std::string &cipherName) { preferredCipher = cipherName; }
	
	void receive (int pDataSocket, std::ostream &outStream);
	
	void send (int pDataSocket, std::istream &inStream, size_t totalSize = 0);
	
	void setPassphrase (const std::string pPassphrase, uint32_t pKeyIterationCount);
private:
	size_t blockSize;
	bool doShowProgress;
	std::string passphrase;
	uint32_t keyIterationCount;
	int dataSocket;
	std::string preferredCipher;
	
	bool secure () const;
	
	void receive_Insecure (std::ostream &outStream);
	void receive_Secure (std::ostream &outStream);
	
	void send_Insecure (std::istream &inStream, size_t totalSize);
	void send_Secure (std::istream &inStream, size_t totalSize);
	
	void writeDataToFile (std::ostream &outStream, const char *data, size_t length);
	size_t fetchDataFromFile (std::istream &inStream, char *data, size_t length);
	
	void writeDataToSocket (const char *data, size_t length);
};

}
