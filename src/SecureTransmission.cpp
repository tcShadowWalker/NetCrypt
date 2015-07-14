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
#include "SymmetricEncryption.h"
#include <stdexcept>
#include <iostream>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>

namespace NetCrypt {

struct TransmissionHeader {
	char _Transmission_Cookie_Value_[SecureMagicCookie.size()];
	uint32_t keyIterationCount;
	uint16_t version = 2;
	uint8_t saltLength;
	uint8_t _padding1_ = 0;
	uint64_t totalSize;
	uint32_t initialBlockSize;
	char _padding2_[8];
	char salt[30];
	char cipherName[30]; // Null-terminated cipher name
	
	inline TransmissionHeader () {
		memcpy (_Transmission_Cookie_Value_, SecureMagicCookie.begin(), SecureMagicCookie.size());
	}
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

void Transmission::receive_Secure (std::ostream &outStream) {
	TransmissionHeader tranInfo;
	if (read (dataSocket, &tranInfo, sizeof(tranInfo)) != sizeof(tranInfo))
		throw std::runtime_error ("Read init error: " + std::string(strerror(errno)));
	if (strncmp (tranInfo._Transmission_Cookie_Value_, SecureMagicCookie.begin(),
				SecureMagicCookie.size()) != 0) {
		throw std::runtime_error ("This is not an encrypted NetCrypt transmission.");
	}
	const std::string usedCipher (tranInfo.cipherName,
							strnlen(tranInfo.cipherName, sizeof(tranInfo.cipherName)));
	Debug ("Using cipher " + usedCipher);
	std::string realPassphrase (Crypt::KeySizeForCipher(usedCipher.c_str()), '\0');
	Crypt::keyDerivation(passphrase.c_str(), passphrase.size(),
						tranInfo.salt, tranInfo.saltLength, keyIterationCount,
						0, (unsigned char*)&realPassphrase[0], realPassphrase.size());
	const size_t ivLen = Crypt::IvSizeForCipher(usedCipher.c_str()),
				tagLen = Crypt::GCM_TAG_LENGTH;
	Debug("IV length: " + std::to_string(ivLen) + ", tag length: "
		+ std::to_string(tagLen) + ", block size: " + std::to_string(tranInfo.initialBlockSize));
	if (DebugEnabled >= 2)
		printDebugCryptoParameters (tranInfo, realPassphrase);
	const size_t HeaderSize = ivLen + tagLen + sizeof(uint32_t);
	std::vector<char> buffer ( tranInfo.initialBlockSize );
	Crypt::Decryption dec (usedCipher.c_str());
	std::string decryptedBlock;
	dec.setOutputBuffer(&decryptedBlock);
	char header[HeaderSize];
	ProgressTracker tracker (tranInfo.totalSize);
	do {
		ssize_t s = recv (dataSocket, header, HeaderSize, MSG_WAITALL);
		if (s == 0 && tranInfo.totalSize == 0)
			break;
		if (s != (ssize_t)HeaderSize)
			throw std::runtime_error ("Read header error: " + std::to_string(s) +
				", " + std::string((errno != 0) ? strerror(errno) : ""));
		if (DebugEnabled >= 3) {
			std::cerr << "IV: " << printableString(std::string(&header[0], ivLen)) << "\n";
			std::cerr << "Tag: " << printableString(std::string(&header[ivLen], tagLen)) << "\n";
		}
		uint32_t blockSize;
		memcpy (&blockSize, &header[ivLen + tagLen], sizeof(blockSize));
		if (blockSize > buffer.size())
			throw std::runtime_error ("Received block size too large");
		size_t receivedPkgBytes = 0;
		while (receivedPkgBytes < blockSize) {
			s = read (dataSocket, &buffer[receivedPkgBytes], blockSize - receivedPkgBytes);
			if (s <= 0)
				throw std::runtime_error ("Read error: " +
					std::string((errno != 0) ? strerror(errno) : ""));
			receivedPkgBytes += s;
		}
		if (DebugEnabled >= 3) {
			std::string hash;
			Crypt::generateHash(buffer.data(), blockSize, &hash);
			std::cerr << "Read payload: " << blockSize << " (Digest: " << hash << ")\n";
		}
		dec.init (realPassphrase, std::string(&header[0], ivLen),
					std::string(&header[ivLen], tagLen));
		dec.feed(buffer.data(), blockSize);
		try {
			dec.finalize();
		} catch (const std::exception &e) {
			throw std::runtime_error ("Decryption failed. Probably the given "
				"passphrase does not match the one used for encryption");
		}
		tracker.add(blockSize);
		if (doShowProgress) {
			tracker.printProgress();
		}
		writeDataToFile (outStream, decryptedBlock.data(), decryptedBlock.size());
	} while (tracker.transferred() < tranInfo.totalSize || tranInfo.totalSize == 0);
	if (doShowProgress)
		std::cerr << "\n";
	Debug ("Total bytes read: " + std::to_string(tracker.totalSize()));
	if (tracker.transferred() < tranInfo.totalSize && tranInfo.totalSize != 0)
		throw std::runtime_error ("Transmission ended prematurely, not all data was received");
}

void Transmission::send_Secure (std::istream &inStream, size_t totalSize) {
	const size_t ivLen = Crypt::IvSizeForCipher(preferredCipher.c_str()),
				tagLen = Crypt::GCM_TAG_LENGTH;
	std::string realPassphrase (Crypt::KeySizeForCipher(preferredCipher.c_str()), '0');
	std::vector<char> buffer (blockSize);
	TransmissionHeader tranInfo;
	tranInfo.saltLength = sizeof(tranInfo.salt);
	Crypt::generateRandomBytes(tranInfo.saltLength, tranInfo.salt);
	Crypt::keyDerivation(passphrase.c_str(), passphrase.size(),
						tranInfo.salt, tranInfo.saltLength, keyIterationCount,
						0, (unsigned char*)&realPassphrase[0], realPassphrase.size());
	tranInfo.keyIterationCount = keyIterationCount;
	tranInfo.totalSize = totalSize;
	tranInfo.initialBlockSize = blockSize;
	strncpy (tranInfo.cipherName, preferredCipher.c_str(), sizeof(tranInfo.cipherName));
	if (DebugEnabled >= 2)
		printDebugCryptoParameters (tranInfo, realPassphrase);
	if (write (dataSocket, &tranInfo, sizeof(tranInfo)) != sizeof(tranInfo))
		throw std::runtime_error ("Write init error: " + std::string(strerror(errno)));
	Crypt::Encryption enc (preferredCipher.c_str());
	std::string outDataBlock;
	enc.setOutputBuffer(&outDataBlock);
	char iv[ivLen + 1];
	ProgressTracker tracker (tranInfo.totalSize);
	const size_t HeaderSize = ivLen + tagLen + sizeof(uint32_t);
	while (true) {
		const size_t r = fetchDataFromFile(inStream, buffer.data(), buffer.size());
		if (r == 0)
			break;
		Crypt::generateRandomBytes(ivLen, iv);
		enc.init (realPassphrase, std::string(iv, ivLen));
		outDataBlock.resize(HeaderSize);
		enc.feed (buffer.data(), r);
		enc.finalize();
		if (DebugEnabled >= 3) {
			if (doShowProgress)
				ProgressTracker::clear();
			std::cerr << "IV: " << printableString(std::string(iv, ivLen)) << "\n";
			std::cerr << "Tag: " << printableString(std::string(enc.tag(), tagLen)) << "\n";
		}
		char *header = &outDataBlock[0];
		const uint32_t blockSize = outDataBlock.size() - HeaderSize;
		memcpy (&header[           0], iv, ivLen);
		memcpy (&header[       ivLen], enc.tag(), tagLen);
		memcpy (&header[ivLen+tagLen], &blockSize, sizeof(blockSize));
		if (DebugEnabled >= 3) {
			std::string hash;
			Crypt::generateHash(&outDataBlock[HeaderSize], blockSize, &hash);
			std::cerr << "Sent: " << r << " (Digest: " << hash << ")\n";
		}
		writeDataToSocket(&outDataBlock[0], outDataBlock.size()); // Write full block. Header + Payload.
		tracker.add(blockSize);
		if (doShowProgress)
			tracker.printProgress();
	}
	if (doShowProgress)
		std::cerr << "\n";
	Debug ("Total bytes sent: " + std::to_string(tracker.totalSize()));
}

}
