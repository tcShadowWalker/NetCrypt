#pragma once
#include <string>
#include <memory>
#include <fstream>

#define NETCRYPT_VERSION "0.5.0"

namespace NetCrypt {

extern bool DebugEnabled;

inline void Debug (const std::string &s) {
	if (DebugEnabled)
		printf ("%s\n", s.c_str());
}

bool stdinIsTerminal ();
bool stdoutIsTerminal ();
bool stderrIsTerminal ();
bool stdinInputAvailable ();
void setTerminalEcho(bool enable);

typedef std::unique_ptr<std::istream> IStreamPtr;
typedef std::unique_ptr<std::ostream> OStreamPtr;

struct DataStream {
	IStreamPtr inPtr;
	OStreamPtr outPtr;
	std::istream *in = nullptr;
	std::ostream *out = nullptr;
	int socket = -1;
	bool transmissionOk = true;
};

enum NetworkOpType {
	NET_NONE = 0,
	NET_LISTEN,
	NET_CONNECT,
};

enum OperationType {
	OP_NONE = 0,
	OP_READ,
	OP_WRITE,
};

struct ProgOpts {
	std::string preferedCipher;
	std::string digest;
	std::string passphrase;
	bool generatePassphrase;
	uint16_t listen_port;
	bool serverMode;
	int compression;
	std::string infile;
	std::string outfile;
	std::string target_host;
	uint16_t target_port;
	unsigned int blockSize;
	unsigned int keyIterationCount;
	NetworkOpType netOp = NET_NONE;
	OperationType op = OP_NONE;
};

}
