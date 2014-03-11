# Protocol for secure file / text exchange
Parameters:
- Exchange between Client(C) and Server(S)
- Both parts have their own private key pairs
- C has S's public key
- S has C's public key

### Message one (begin handshake)
Client sends to Server
``` {payload: E_Us(c_id, N_c), sig: signed(payload)} ```
- JSON for easy parsability
- id = client id, identifies its public key
- payload = encrypted nonce
- sig = signed id+payload to prevent modification

if c_id is known, and signature is valid:
    At this point, the server knows the message was sent by client one, but it might be a replay
    The nonce is hidden and only readable by the server

### Mesage two (accept handshake)
Server replies to Client
``` {payload: E_Uc(N_c+1, N_s, K_CS), sig: signed(payload)} ```
- payload = encrypted N_c reply and N_s
- sig = signed payload to prevent modification
- K_CS = server-generated secret key for next exchange

if N_c+1 is correct and signature matches:
    Now the client trusts the server.
    Server doesnt trust client yet though
    K_CS is now known to be a fresh and secure secret key

### Message Three (complete & request)
Client replies to Server
``` {payload: E_Us(N_s+1), sig: signed(payload), operation: K_CS(operation)} ```

if N_s+1 is correct and signature matches:
    Now the server trusts the client
    if operation can be decrypted using K_CS
        perform op. update the signed hash

### Message Four (response)
Server replies to Client and closes connection
``` {payload: K_CS(response)} ```

connection closed

# Attacks

interception:
message_one: attacker can't descrypt payload, can't identify client
             attacker can't verify message as it doesn't know client public key
             attacker CAN replay this message

message_two: attacker can't decrypt payload
             attacker CAN verify that the message came from server
             attacker can't replay this message due to nonces





