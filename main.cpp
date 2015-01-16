#include "SymmetricEncryption.h"
#include <iostream>
#include <string>
#include <vector>
#include <boost/program_options.hpp>
#include <unistd.h>
#include <sys/poll.h>
#include <fstream>

#define JPSNET_VERSION "0.1.2"

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
	NetworkOpType netOp = NET_NONE;
	OperationType op = OP_NONE;
};

bool evaluateOptions (int argc, char **argv, ProgOpts *opt) {
	namespace po = boost::program_options;
	po::options_description general_desc("General");
	general_desc.add_options()
		("help", "Produce this help message")
		("version", "Print version string and quit")
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
};


void determineInOut (DataStream *dstream, ProgOpts *opt) {
	if (opt->infile != "") {
		opt->op = OP_READ;
		dstream->inPtr.reset(new std::ifstream (opt->infile, std::ios::in));
		dstream->in = dstream->inPtr.get();
	} else if (stdinInputAvailable() && !stdinIsTerminal()) {
		opt->op = OP_READ;
		dstream->in = &std::cin;
	}
	if (opt->outfile != "") {
		if (opt->op != OP_NONE)
			throw boost::program_options::error("Cannot perform both input and output in one operation");
		opt->op = OP_WRITE;
		dstream->outPtr.reset(new std::ofstream (opt->outfile, std::ios::out));
		dstream->out = dstream->outPtr.get();
	} else if (opt->op == OP_NONE) {
		if (!stdoutIsTerminal()) {
			dstream->out = &std::cout;
			opt->op = OP_WRITE;
		} else {
			throw boost::program_options::error("No mode of operation specified. "
			"Use either --infile or --outfile.");
		}
	}
	assert (dstream->in || dstream->out);
}

int main (int argc, char **argv) {
	ProgOpts progOpt;
	try {
		if (!evaluateOptions (argc, argv, &progOpt))
			return 1;
		assert (progOpt.netOp != NET_NONE);
		DataStream dStream;
		determineInOut (&dStream, &progOpt);
		assert (progOpt.op != OP_NONE);
	} catch (const std::exception &e) {
		std::cerr << "Error parsing command line options:\n" << e.what() << "\n";
		return 1;
	}
	
}
