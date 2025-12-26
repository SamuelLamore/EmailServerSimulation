# Email Server Simulation
Command Line based simulation of an email service using public key crypto, hashing, and simple protocols.
Made for CS492 Final Project at CCSU in Summer 2025

# Description
This application simulates an email service involving a client and a server.

The user can create accounts with a username and password. The “server” stores a hash of the password (with salt) instead of the password itself, and it also generates a public key and a private key for the user with RSA. The public key is stored as plaintext, as it is supposed to be public, but the private key is encrypted using an AES symmetric key generated based on the user’s password. When you write an email and choose an account to send it to, the email gets signed by you, and it gets encrypted for the recipient. When you read emails from your inbox, your private key is used to decrypt those emails, and the signature is verified.
In addition, before logging in, the program goes through a simple protocol to authenticate the server. It passes a challenge (nonce) to the server, encrypted with the server’s public key. The server then authenticates itself by decrypting the nonce with its private key, and returning a signature of the nonce.

Important Note: in this program, the server’s private key is stored in plaintext inside the codebase. This is definitely not secure and is only done for demonstration purposes. In the case of a real server environment, a private key should never be stored like this, but in the context of this simulation program where the “server” and “client” are functionally the same, and the entire program and database are stored & ran on the user’s machine, it seemed pointless to come up with a method to further secure the private key. While some obfuscation technique, or other software reverse engineering prevention methods like anti-debugging or anti-disassembly could have been used, they felt outside of the scope of this project. Such techniques also would only be used in this case to solve a problem that wouldn’t even exist in a real server environment anyway.
