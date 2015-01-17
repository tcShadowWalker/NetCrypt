# NetCrypt
Secure network file tansmission using authenticated encryption.

NetCrypt is a small tool providing authentication, confidentiality and integrity validation
while still maintaining top-notch performance and transfer speed between machines.
No public key distribution is required:
NetCrypt is designed to use a symmetric passphrase with a strong key-derivation-function.

Have you ever wanted to quickly copy files or devices between different machines over the network?
You can use tools like netcat. However, netcat transmision is insecure and doesn't provide
any kind of authentication or confidentiality.
One might additionally use the OpenSsl enc utility to provide confidentiality,
but that does not support authenticated encryption and the transmission occurs without integrity validation.
Using OpenSSH provides all that, but unfortunately, SSH is unbearably slow to transfer files when using a secure cipher.

NetCrypt seeks to fulfill all those requirements.
In it's default configuration, NetCrypt uses the AES-256-GCM cipher with a PBKDF2 key iteration count of 32000 rounds.
