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

#include <string>
#include <memory>
#include <fstream>

#define NETCRYPT_VERSION "0.4.9"

namespace NetCrypt {

extern int DebugEnabled;
constexpr std::initializer_list<char> SecureMagicCookie {'N', 'E', 'T', 'C', 'R', 'Y', 'P', 'T', '_', 'S', 'E', 'C'};

inline void Debug (const std::string &s) {
	if (DebugEnabled)
		printf ("%s\n", s.c_str());
}

typedef std::unique_ptr<std::ifstream> IStreamPtr;
typedef std::unique_ptr<std::ofstream> OStreamPtr;

struct DataStream {
	IStreamPtr inPtr;
	OStreamPtr outPtr;
	std::istream *in = nullptr;
	std::ostream *out = nullptr;
	uint64_t totalSize = 0;
};

enum NetworkOpType {
	NET_NONE = 0,
	NET_LISTEN,
	NET_CONNECT,
};

}
