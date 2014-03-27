# 1 Secure File Storage
Part one could be split into 2 logical sections:
Performing a 3 way handshake in order to authenticate a client and server
Communicating over secure channel
## 1.1 Performing a 3 way handshake
Since the client and server have both their own private keys as well as each others public keys, three way authentication can be performed. The end goal is for both parties to authenticate and to provide proof of freshness. Three messages are exchanged hence the name: 3 way handshake. We also use this to exchange a symmetric AES key for the next section.

RSA keys used are all 2048bit and use PKCS#1 padding and ECB mode for encryption and decryption.

The AES keys are 256bit and PKCS#5 padding is used.

### Message 1 - Client sends to Server
Purpose: Client sends its identity, allows server to pick correct public key.
```
message = {
id: ‘client_one’,
cnonce: <random_nonce>
}

SEND E_server_pub(message), E_client_priv(hash(message))
```
Result: If the server has a public key for this client, the server can verify the message, otherwise it can reject the connection entirely.

### Message 2 - Server sends to Client
Purpose: Server provides proof of identity and freshness by being able to decrypt the nonce and id. Server provides an AES key for the secure channel.
```
message = {
        cnonce: cnonce+1,
        snonce: <random_nonce>,
        sessionkey: <random_aes_key>,
        sessioniv: <random_aes_iv>
}

SEND E_client_pub(message), E_server_priv(hash(message))
```
Result: Client now trusts Server, since Server proves its identity by being able to decrypt the previous message and proves freshness by returning the correct nonce value. Client and Server now both share an AES key for the secure channel.

### Message 3 - Client sends to Server
Purpose: Client must now prove its identity and freshness. It also proves that it can use the AES key by sending some encrypted text.
```
message = {
snonce: snonce+1,
cnonce: <random_nonce>
}
plaintext = ‘abcdefghijklmnopqrstuvwxyz’

SEND E_server_pub(message), E_client_priv(hash(message)), E_aes(plaintext)
```
Results: Server now trusts Client as Client has provided the correct nonce and was able to use the AES key. At this point, Client and Server are both authenticated and have shared a symmetric key.

## 1.2: Communicating over secure channel
Since the Client and Server now share an AES key, they can stop using RSA encryption and move over to using only AES. Nonces are still used to prevent replay attacks. An initial message is sent back to the client to indicate the server is ready, and from then on the client sends commands to the server and the server sends a response back each time.

### Initial Message - Server sends to Client ‘READY’
Purpose: Server indicates it is ready to receive commands
```
message = {
response: 0,
message: 'ready',
cnonce: cnonce+1,
snonce: <random_nonce>
}

SEND E_aes(message)
```
### Commands - Client sends to Server
```
message = {
    action: ‘upload’ or ‘get’ or ‘hash_check’,
    cnonce: <random_nonce>,
    snonce: snonce+1,
    <other_fields>
}

SEND E_aes(message)
```

### Responses - Server sends to Client
```
message = {
    response: <0=success, 1=failure>,
message: <status message>,
cnonce: cnonce+1,
snonce: <random_nonce>,
<other_fields>
}

SEND E_aes(message)
```

## 1.3: Available Commands
Three commands are available to the client:
* Upload - upload a customers.dat file to the remote server. Each line in the customers.dat file is in the form: “IDXXX-some details string”
* Get - get the details string for the given ID
* Hash_check - submit an ID and a hash value to confirm whether the calculated hash matches the remote hash
* Quit - tells the server to abort the connection

## 1.4: Secure File Storage
Before the client uploads the customers lines to the server, each line is converted into a secure form:
```
<ID>-<DETAILS> ⇒ <ID>||E_aes(<DETAILS>)||hash(<ID>||<DETAILS>)
```
The AES key is a master key stored by the client and never revealed to any other party.

Once the server receives the customers lines, the server calculates a hash of each line and appends a signed version to the end so that each line is stored remotely as:
```
<line>||E_server_priv(hash(<line>))
```
This allows the server to check for data corruption or modification whenever a client requests a specific line or hash.

## 1.5 Attack Vectors
### 1.5.1 Replay of Message One
Replay attack available as no nonces have been transferred yet. Server will respond with message but attacker will not be able to read contents as they are only decryptable by correct client’s private key.

### 1.5.2 Interception
No messages are readable by a Man In The Middle (MITM). Messages in the 3-way handshake are only decryptable by the correct party, and messages in the secure channel are decryptable only by the correct key which is unique per connection.

### 1.5.3 Interruption
To prevent denial of service, the Server can handle multiple connections to the same socket at once. If an attacker locks up one thread, another thread is spawned for a new connection.

### 1.5.4 Modification
Server and Client can verify the integrity of messages in the 3-way handshake by checking the signed hash of the data. Messages in the secure channel cannot be modified without causing errors when the message is decrypted.

### 1.5.5 Fabrication
Messages can’t be fabricated without an attacker knowing either the private keys, or the secure channel key.

### 1.5.6 Access to data file
If an attacker gains access to the secure data file, they will not be able to read the details lines, as these are only decryptable by the master key stored on the Client. Any modification of the encrypted contents or ID will be picked up by the Server and reported as corrupted lines.

### 1.5.7 Access to keyrings
If an attacker gains access to the private key of the Server, an attacker could read the commands being sent and received by the Client and Server and possibly inject malicious packets to modify the random AES key and thus gain access to the secure channel. The attacker will not be able to ever read the secure file contents without the master key that is only ever used by the Client.

If an attacker gains access to the private key and master key of a Client, the attacker could upload a new data file or retrieve any details for any ID. This would be a fully compromised system. To stop this attack, an administrator would remove the Client’s public key from the Server, thereby revoking access.