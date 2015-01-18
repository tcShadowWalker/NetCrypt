#include "NetCrypt.h"
#include "SymmetricEncryption.h"
#include <boost/program_options.hpp>
#include <unistd.h>
#include <iostream>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <termios.h>
#include "Progress.h"
#include <sys/ioctl.h>
#include <stdio.h>

namespace NetCrypt {

bool stdinIsTerminal () { return isatty(fileno(stdin)); }
bool stdoutIsTerminal () { return isatty(fileno(stdout)); }
bool stderrIsTerminal () { return isatty(fileno(stdin)); }
void setTerminalEcho(bool enable) {
	struct termios tty;
	tcgetattr(STDIN_FILENO, &tty);
	if( !enable )
		tty.c_lflag &= ~ECHO;
	else
		tty.c_lflag |= ECHO;
	(void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

ProgressTracker::ProgressTracker (size_t pTotal) {
	mTotalSize = pTotal;
	mTransferred = 0;
	mStartTime = std::chrono::system_clock::now();
}

void ProgressTracker::printProgress () {
	using namespace std::chrono;
	const system_clock::time_point last = system_clock::now();
	const milliseconds::rep millisec = duration_cast<milliseconds>(last - mStartTime).count();
	const float totalTimeSec = millisec / 1000;
	const float mbPerSecond = (mTransferred / totalTimeSec) / 1024 / 1024;
	if (mTotalSize == 0) {
		fprintf (stderr, "%.3f MB/s, Bytes: %lu, Time: %.1f s\r",
				mbPerSecond, mTransferred, totalTimeSec);
	} else {
		const float ratio = ((float)mTransferred) / mTotalSize;
		fprintf (stderr, "%.1f%% done,  %.3f MB/s, Bytes: %lu / %lu, Time: %.1f s\r",
				ratio * 100, mbPerSecond, mTransferred, mTotalSize, totalTimeSec);
	}
}

void ProgressTracker::clear () {
	struct winsize w;
    ioctl(STDERR_FILENO, TIOCGWINSZ, &w);
	char line[w.ws_col + 1];
	memset (line, ' ', w.ws_col);
	line[w.ws_col] = '\0';
	fprintf (stderr, "%s\n", line);
}

bool evaluateOptions (int argc, char **argv, ProgOpts *opt) {
	namespace po = boost::program_options;
	po::options_description general_desc("General");
	general_desc.add_options()
		("help", "Produce this help message")
		("version", "Print version string and quit")
		("debug", po::value(&DebugEnabled)->default_value(0)->implicit_value(1),
			"Enable debug output.\n1 - print informative output.\n"
			"2 - output cryptographic data in encoded cleartext.\n"
			"3 - print metadata about all transmitted packages")
	;
	po::options_description cfg_desc("Program options");
	cfg_desc.add_options()
		("listen,l", po::value(&opt->listen_port) /*->value_name("port")*/,
			"Listen on port")
		("infile,i", po::value(&opt->infile) /*->value_name("filename")*/,
			"Input file or device to read from")
		("outfile,o", po::value(&opt->outfile) /*->value_name("filename")*/,
			"Output file or device to  write to")
		("host,h", po::value(&opt->target_host) /*->value_name("hostname")*/,
			"Hostname to connect to")
		("port,p", po::value(&opt->target_port), "Target port to connect to")
		("once", po::bool_switch(&opt->acceptOnce)->default_value(false),
			"Accept only one incomming connection and exit after transmission. "
			"Only useful in listening mode. Automatically enabled when reading from stdin.")
		("compression", po::value(&opt->compression) /*->value_name("algorithm")*/,
			"Set compression algorithm")
		("cipher", po::value(&opt->preferedCipher)
			->default_value("aes-256-gcm"), "Choice of encryption cipher.")
		("digest", po::value(&opt->digest)
			->default_value("sha-256"), "Name of secure message digest algorithm")
		("blocksize", po::value(&opt->blockSize)->default_value(32768), "Transmission block size")
		("genpass", po::bool_switch(&opt->generatePassphrase)->default_value(false),
			"Generate a random passphrase and print it on stderr. "
			"This only makes sense in 'listening' mode, and when stderr is connected to a TTY.")
		("key-iterations", po::value(&opt->keyIterationCount)->default_value(32768),
			"Key iteration count for key derivation function PBKDF2")
		("non-interactive", "Do not read password interactively from stdin, if not set in environment variable")
		("no-progress", "Do not show progress and speed of transfer.\n"
			"Otherwise, a progress meter is shown when used interactively"
		)
		// TODO
		// ("no-encryption", po::bool_switch(&opt->noEncrypt),
		//	 "Disable authenticated encryption. Insecure plaintext transmission.")
	;
	po::options_description passphrase_desc("Passphrase options");
	passphrase_desc.add_options()
		("passphrase", po::value(&opt->passphrase), "Passphrase for encryption")
	;
	po::variables_map vm;
	po::options_description cmdline_options;
	cmdline_options.add(cfg_desc).add(general_desc);
	po::store(po::parse_command_line(argc, argv, cmdline_options), vm);
	po::store(po::parse_environment(passphrase_desc, "NETCRYPT_"), vm);
	po::notify(vm);
	if (argc == 1 || vm.count("help")) {
		const char *exe = (argc > 0) ? argv[0] : "netcrypt";
		std::cout << "NetCrypt " << NETCRYPT_VERSION <<
			" - Secure network transfer using authenticated encryption.\n"
			"Basic usages:\n" << "export NETCRYPT_PASSPHRASE=\"yourPassphrase\"\n"
			<< "Listen for inbound:\t" << exe << " -l port -i input_file.txt\n"
			<< "Connect to remote:\t" << exe << " -h target_host -p port -o output.txt\n"
			<< cmdline_options << "\n";
		return false;
	} else if (vm.count("version")) {
		std::cout << "Netcrypt version " << NETCRYPT_VERSION << "\n";
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
		if (vm.count("non-interactive") == 0) {
			if (!stdinIsTerminal() || !stderrIsTerminal())
				throw boost::program_options::error("No password availabe and interactive "
					"passphrase entry is only allowed from a tty");
			std::cerr << "Passphrase: ";
			setTerminalEcho(false);
			std::getline(std::cin, opt->passphrase);
			setTerminalEcho(true);
			std::cerr << std::endl;
		}
		if (opt->passphrase.empty())
			throw boost::program_options::error("Please specify a password using the environment variable NETCRYPT_PASSPHRASE");
	}
	if (vm.count("no-progress") > 0)
		opt->showProgress = false;
	// Check that cipher name is valid
	(void)Crypt::KeySizeForCipher(opt->preferedCipher.c_str());
	return true;
}

void openInOutStream (DataStream *dstream, ProgOpts *opt) {
	if (opt->infile != "") {
		opt->op = OP_WRITE;
		Debug("Input from file " + opt->infile);
		struct stat st;
		if (stat (opt->infile.c_str(), &st) == 0) {
			dstream->totalSize = st.st_size;
			Debug("Input file total size: " + std::to_string(st.st_size));
		} else
			Debug("stat() failed on input file");
		dstream->inPtr.reset(new std::ifstream (opt->infile, std::ios::in));
		if (!dstream->inPtr->is_open())
			throw std::runtime_error ("Could not open input file " + opt->infile);
		dstream->in = dstream->inPtr.get();
	} else if (!stdinIsTerminal()) {
		opt->op = OP_WRITE;
		Debug("Input from Stdin");
		if (!opt->acceptOnce && opt->netOp == NET_LISTEN) {
			opt->acceptOnce = true;
			Debug("Enabling 'acceptOnce' flag");
		}
		dstream->in = &std::cin;
	}
	if (opt->outfile != "") {
		if (opt->op != OP_NONE)
			throw boost::program_options::error("Cannot perform both input and output in one operation");
		opt->op = OP_READ;
		opt->acceptOnce = true; // this option is useless in read mode.
		Debug("Output to file " + opt->outfile);
		dstream->outPtr.reset(new std::ofstream (opt->outfile, std::ios::out));
		if (!dstream->outPtr->is_open())
			throw std::runtime_error ("Could not open output file " + opt->outfile);
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

