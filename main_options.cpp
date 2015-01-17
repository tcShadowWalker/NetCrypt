#include "JpsNet.h"
#include "SymmetricEncryption.h"
#include <boost/program_options.hpp>
#include <unistd.h>
#include <iostream>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>

namespace JpsNet {

bool stdinIsTerminal () { return isatty(fileno(stdin)); }
bool stdoutIsTerminal () { return isatty(fileno(stdout)); }
bool stderrIsTerminal () { return isatty(fileno(stdin)); }

bool stdinInputAvailable () {
	struct pollfd fds;
	int ret;
	fds.fd = fileno(stdin);
	fds.events = POLLIN;
	ret = poll(&fds, 1, 0);
	return (ret == 1);
}

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
		("listen,l", po::value(&opt->listen_port)->value_name("port"),
			"Listen on socket")
		("infile,i", po::value(&opt->infile)->value_name("filename"),
			"Input file or device to read from")
		("outfile,o", po::value(&opt->outfile)->value_name("filename"),
			"Output file or device to  write to")
		("host,h", po::value(&opt->target_host)->value_name("hostname"),
			"Hostname to connect to")
		("port,p", po::value(&opt->target_port), "Target port to connect to")
		("compression", po::value(&opt->compression)->value_name("algorithm"),
			"Set compression level")
		("cipher", po::value(&opt->preferedCipher)->value_name("name")
			->default_value("aes-256-gcm"), "Choice of encryption cipher.")
		("digest", po::value(&opt->digest)->value_name("name")
			->default_value("sha-256"), "Name of secure message digest algorithm")
		("blocksize", po::value(&opt->blockSize)->default_value(32768), "Transmission block size")
		("genpass", po::bool_switch(&opt->generatePassphrase)->default_value(false),
			"Generate a random passphrase and print it on stderr. "
			"This only makes sense in 'listening' mode, when stderr is connected to a TTY.")
		("iterations", po::value(&opt->keyIterationCount)->default_value(32768),
			"Key iteration count for key derivation function PBKDF2")
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
	if (opt->generatePassphrase) {
		if (!stderrIsTerminal())
			throw boost::program_options::error("To generate a passphrase, stderr must "
				"be connected to an interactive tty");
		if (opt->netOp != NET_LISTEN)
			throw boost::program_options::error("Generating a passphrase is only useful "
				"when waiting for incoming connections");
		std::string rawPwd = Crypt::generateRandomString(Crypt::KeySizeForCipher(opt->preferedCipher.c_str()));
		opt->passphrase.resize(rawPwd.size() * 2);
		Crypt::uc2sc(&opt->passphrase[0], (const unsigned char*)rawPwd.data(), rawPwd.size());
		std::cerr << "Generated passphrase: " << opt->passphrase << std::endl;
	}
	if (opt->passphrase.empty()) {
		throw boost::program_options::error("Please specify a password using the environment variable JPSNET_PASSPHRASE");
	}
	return true;
}

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

}

