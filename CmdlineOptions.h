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

bool stdinIsTerminal ();
bool stdoutIsTerminal ();
bool stderrIsTerminal ();
void setTerminalEcho(bool enable);

enum OperationType {
	OP_NONE = 0,
	OP_READ,
	OP_WRITE,
};

struct ProgOpts {
	std::string preferredCipher;
	std::string digest;
	std::string passphrase;
	bool generatePassphrase;
	uint16_t listen_port;
	bool acceptOnce;
	int compression;
	std::string infile;
	std::string outfile;
	std::string target_host;
	uint16_t target_port;
	unsigned int blockSize;
	unsigned int keyIterationCount;
	bool showProgress = true;
	bool useEncryption = true;
	NetworkOpType netOp = NET_NONE;
	OperationType op = OP_NONE;
};

}