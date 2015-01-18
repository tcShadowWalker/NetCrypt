#pragma once
#include <string>
#include <memory>
#include <fstream>

#define NETCRYPT_VERSION "0.5.0"

namespace NetCrypt {

extern int DebugEnabled;

inline void Debug (const std::string &s) {
	if (DebugEnabled)
		printf ("%s\n", s.c_str());
}

bool stdinIsTerminal ();
bool stdoutIsTerminal ();
bool stderrIsTerminal ();
bool stdinInputAvailable ();
void setTerminalEcho(bool enable);

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
	bool acceptOnce;
	int compression;
	std::string infile;
	std::string outfile;
	std::string target_host;
	uint16_t target_port;
	unsigned int blockSize;
	unsigned int keyIterationCount;
	bool showProgress;
	NetworkOpType netOp = NET_NONE;
	OperationType op = OP_NONE;
};

}
