<img style="float: right" src="http://jp-dev.org/netcrypt/NetCrypt.png" />
# NetCrypt
Secure network file tansmission using authenticated encryption.

<p><i>NetCrypt</i> is a small Open Source tool providing <b>authentication</b>, <b>confidentiality</b> and <b>integrity validation</b> while still maintaining top-notch <b>performance</b> and transfer speed between machines.
No public key distribution is required: NetCrypt is designed to use a symmetric passphrase with a strong key-derivation-function.</p>
<p>Have you ever wanted to quickly copy files or devices between different machines over the network
You can use tools like netcat. However, netcat transmision is insecure and doesn't provide any kind of authentication or confidentiality.
One might additionally use the OpenSsl enc cmdline utility to provide confidentiality,
but that does not support authenticated encryption and the transmission happens without integrity validation.<br />
Using OpenSSH provides all that, but unfortunately, SSH is unbearably slow when using a secure cipher.</p>

<p>NetCrypt seeks to fulfill all those requirements.<br />
In it's default configuration, it uses the <i>AES-256-GCM</i> cipher with a PBKDF2 key iteration count of 32000 rounds.</p>

## Usage
<pre>
export NETCRYPT_PASSPHRASE="yourPassphrase"
\# Listen on incoming connections on port 9000, serve connectin clients the file 'input.txt'
netcrypt -l 9000 -i input.txt
\# Connect to localhost port 9000, store contents in output.txt
netcrypt -h localhost -p 9000 -o output.txt
</pre>
You can also copy entire directories using tar (bzip2 compressed):<pre>
tar -cj . | netcrypt -l 9000 
netcrypt -h localhost -p 9000 | tar -xj
</pre>
During the transfer, you will see a nice progress bar showing the transfer speed:<pre>
  80.6% done,  56.495 MB/s, Bytes: 118479039 / 146996326, Time: 2.02 s </pre>
To generate a random passphrase, you might use the --genpass option.

### Licsensing
NetCrypt is licensed under GPL 2.<br/>
See the LICENSE file in the project root folder.

### Contributors
- Jan-Philip Stecker
