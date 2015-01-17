#include "SymmetricEncryption.h"
#include <iostream>
#include <string>
#include <vector>
#include <boost/program_options.hpp>
#include <unistd.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fstream>
#include <netdb.h>
#include <stdexcept>
#include <array>
#include <arpa/inet.h>
#include <signal.h>

#define JPSNET_VERSION "0.1.2"

bool DebugEnabled = false;

void Debug (const std::string &s) {
	if (DebugEnabled)
		printf ("%s\n", s.c_str());
}

bool stdinInputAvailable () {
	struct pollfd fds;
	int ret;
	fds.fd = fileno(stdin);
	fds.events = POLLIN;
	ret = poll(&fds, 1, 0);
	return (ret == 1);
}

bool stdinIsTerminal () { return isatty(fileno(stdin)); }
bool stdoutIsTerminal () { return isatty(fileno(stdout)); }

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
	std::string cipher;
	std::string passphrase;
	uint16_t listen_port;
	int compression;
	std::string infile;
	std::string outfile;
	std::string target_host;
	uint16_t target_port;
	unsigned int blockSize;
	NetworkOpType netOp = NET_NONE;
	OperationType op = OP_NONE;
};

bool evaluateOptions (int argc, char **argv, ProgOpts *opt) {
	namespace po = boost::program_options;
	po::options_description general_desc("General");
	general_desc.add_options()
		("help", "Produce this help message")
		("version", "Print version string and quit")
		("debug", po::bool_switch(&DebugEnabled), "Enable debug output")
	;
	po::options_description cfg_desc("Program options");
	cfg_desc.add_options()
		//("pass", po::value(&opt->passphrase)->required(), "Passphrase for encryption")
		("cipher", po::value(&opt->cipher)->value_name("name")
			->default_value("aes-256-gcm"), "Choice of encryption cipher.")
		("listen,l", po::value(&opt->listen_port)->value_name("port"), "Listen on socket")
		("infile,i", po::value(&opt->infile)->value_name("filename"), "Input file or device to read from")
		("outfile,o", po::value(&opt->outfile)->value_name("filename"), "Output file or device to  write to")
		("host,h", po::value(&opt->target_host)->value_name("hostname"), "Hostname to connect to")
		("port,p", po::value(&opt->target_port), "Target port to connect to")
		("compression", po::value(&opt->compression)->value_name("algorithm"), "Set compression level")
		("blocksize", po::value(&opt->blockSize)->default_value(32768), "Transmission block size")
	;
	po::options_description passphrase_desc("Passphrase options");
	passphrase_desc.add_options()
		("passphrase", po::value(&opt->passphrase), "Passphrase for encryption")
	;
	po::variables_map vm;
	po::options_description cmdline_options;
	cmdline_options.add(general_desc).add(cfg_desc);
	po::store(po::parse_command_line(argc, argv, cmdline_options), vm);
	po::store(po::parse_environment(passphrase_desc, "JPSNET_"), vm);
	po::notify(vm);
	if (argc == 1 || vm.count("help")) {
		std::cout << cmdline_options << "\n";
		return false;
	} else if (vm.count("version")) {
		std::cout << "JpsNet version " << JPSNET_VERSION << "\n";
		return false;
	}
	if (vm.count("listen") > 0)
		opt->netOp = NET_LISTEN;
	if (vm.count("host") > 0) {
		if (opt->netOp != NET_NONE)
			throw boost::program_options::error("Cannot perform multiple network modes");
		if (vm.count("port") != 1)
			throw boost::program_options::error("A target port is required in 'connect' mode");
		opt->netOp = NET_CONNECT;
	}
	if (opt->netOp == NET_NONE) {
		throw boost::program_options::error("You did not specify a mode of network mode. "
			"Use either connect or listen mode.");
	}
	if (opt->passphrase == "") {
		throw boost::program_options::error("Please specify a password using the environment variable JPSNET_PASSPHRASE");
	}
	return true;
}

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


void determineInOut (DataStream *dstream, ProgOpts *opt) {
	if (opt->infile != "") {
		opt->op = OP_WRITE;
		Debug("Input from file " + opt->infile);
		if (DebugEnabled) {
			struct stat st;
			if (stat (opt->infile.c_str(), &st) == 0)
				Debug("Input file total size: " + std::to_string(st.st_size));
			else
				Debug("stat() failed on input file");
		}
		dstream->inPtr.reset(new std::ifstream (opt->infile, std::ios::in));
		dstream->in = dstream->inPtr.get();
	} else if (stdinInputAvailable() && !stdinIsTerminal()) {
		opt->op = OP_WRITE;
		Debug("Input from Stdin");
		dstream->in = &std::cin;
	}
	if (opt->outfile != "") {
		if (opt->op != OP_NONE)
			throw boost::program_options::error("Cannot perform both input and output in one operation");
		opt->op = OP_READ;
		Debug("Output to file " + opt->outfile);
		dstream->outPtr.reset(new std::ofstream (opt->outfile, std::ios::out));
		dstream->out = dstream->outPtr.get();
	} else if (opt->op == OP_NONE) {
		if (!stdoutIsTerminal()) {
			Debug("Output on Stdout");
			dstream->out = &std::cout;
			opt->op = OP_READ;
		} else {
			throw boost::program_options::error("No mode of operation specified. "
			"Use either --infile or --outfile.");
		}
	}
	assert (dstream->in || dstream->out);
}

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
			dStream.socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
			if (dStream.socket < 0)
				continue;
			getnameinfo((const sockaddr*)res->ai_addr, res->ai_addrlen,
						addr_ascii.data(), addr_ascii.size() - 1, 0, 0, 0);
			Debug(std::string("Connecting to ") + addr_ascii.data());
			if (connect(dStream.socket, res->ai_addr, res->ai_addrlen) == 0) {
				break;
			}
			close(dStream.socket);
			dStream.socket = -1;
		}
		freeaddrinfo(results);
		if (dStream.socket == -1)
			throw std::runtime_error ("Failed to establish connection: " + std::string(strerror(errno)));
		*dataSocket = dStream.socket;
	} else if (pOpt.netOp == NET_LISTEN) {
		dStream.socket = socket(AF_INET6, SOCK_STREAM, 0);
		if (dStream.socket < 0)
			throw std::runtime_error ("Failed to open socket: " + std::string(strerror(errno)));
		int reuseaddr = 1;
		if (setsockopt(dStream.socket, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) != 0)
			throw std::runtime_error ("Failed to set socket options: " + std::string(strerror(errno)));
		sockaddr_in6 addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin6_addr = IN6ADDR_ANY_INIT;
		addr.sin6_family = AF_INET6;
		addr.sin6_port = htons(pOpt.listen_port);
		if (bind(dStream.socket, (const sockaddr*)&addr, sizeof(addr)) != 0)
			throw std::runtime_error ("Failed to bind socket: " + std::string(strerror(errno)));
		if (listen(dStream.socket, 1) != 0)
			throw std::runtime_error ("Failed to listen on socket: " + std::string(strerror(errno)));
		struct sockaddr_storage client_addr;
		socklen_t addr_len = sizeof(client_addr);
		*dataSocket = accept (dStream.socket, (sockaddr*)&client_addr, &addr_len);
		if (*dataSocket == -1)
			throw std::runtime_error ("Failed to accept connection: " + std::string(strerror(errno)));
		getnameinfo((const sockaddr*)&client_addr, addr_len,
						addr_ascii.data(), addr_ascii.size() - 1, 0, 0, 0);
		Debug(std::string("Connection from ") + addr_ascii.data());
	}
	assert (dStream.socket != -1);
}

void handleIncomingData (DataStream &dStream, const char *data, size_t length) {
	dStream.out->write(data, length);
}

size_t fetchData (DataStream &dStream, char *data, size_t length) {
	dStream.in->read(data, length);
	ssize_t r = dStream.in->gcount();
	return r;
}

void sendReceiveData (const ProgOpts &pOpt, DataStream &dStream, int dataSocket) {
	assert (dataSocket != -1);
	std::vector<char> buffer (pOpt.blockSize);
	size_t totalByteCount = 0;
	if (pOpt.op == OP_READ) {
		assert (dStream.out != nullptr);
		while (true) {
			const ssize_t s = read (dataSocket, buffer.data(), buffer.size());
			if (s == 0)
				break;
			else if (s < 0)
				throw std::runtime_error ("Read error: " + std::string(strerror(errno)));
			Debug("Read: " + std::to_string(s));
			totalByteCount += s;
			handleIncomingData (dStream, buffer.data(), (size_t)s);
		}
		Debug ("Total bytes read: " + std::to_string(totalByteCount));
	} else if (pOpt.op == OP_WRITE) {
		assert (dStream.in != nullptr);
		while (true) {
			const size_t r = fetchData(dStream, buffer.data(), buffer.size());
			if (r == 0)
				break;
			Debug("Send: " + std::to_string(r));
			if (write (dataSocket, buffer.data(), r) != r) {
				throw std::runtime_error ("Write error: " + std::string(strerror(errno)));
			}
			totalByteCount += r;
		}
		Debug ("Total bytes sent: " + std::to_string(totalByteCount));
	}
}

int main (int argc, char **argv) {
	ProgOpts progOpt;
	DataStream dStream;
	try {
		if (!evaluateOptions (argc, argv, &progOpt))
			return 1;
		assert (progOpt.netOp != NET_NONE);
		Debug(std::string("Network mode: ") + ( (progOpt.netOp == NET_LISTEN) ? "Listen" : "Connect" ));
		determineInOut (&dStream, &progOpt);
		assert (progOpt.op != OP_NONE);
		Debug(std::string("Network operation: ") + ( (progOpt.op == OP_READ) ? "Read" : "Write" ));
	} catch (const std::exception &e) {
		std::cerr << "Error parsing command line options:\n" << e.what() << "\n";
		return 1;
	}
	signal(SIGPIPE, SIG_IGN);
	int dataSocket;
	try {
		openNetDevice (progOpt, dStream, &dataSocket);
	} catch (const std::exception &e) {
		std::cerr << "Networking error: " << e.what() << "\n";
		return 1;
	}
	try {
		sendReceiveData (progOpt, dStream, dataSocket);
		close(dStream.socket);
	} catch (const std::exception &e) {
		std::cerr << "Operation error: " << e.what() << "\n";
		return 1;
	}
	return (dStream.transmissionOk == true) ? 0 : 1;
}
