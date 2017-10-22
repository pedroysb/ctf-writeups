After reversing the client, you can see that it has the enclave.butcher.team address.
This address is a remote SGX enclave, where you can query the encrypted flag or perform a remote
attestion and be able to decrypt the flag.

The remote attestation process is described here: 
https://software.intel.com/en-us/articles/intel-software-guard-extensions-remote-attestation-end-to-end-example

The implementation is in solve.py

$ python solve.py 
[+] Opening connection to enclave.butcher.team on port 8088: Done
Hello there!
What would you like to do?
1: Get flag.
2: Prove I'm worthy.
3: Abort.

Let's see if you can do this...
Give me your public key encoded as base64.

Here goes MSG1 encoded as base64:
zeLbDnOQ6QlEYeDcPZdcNt5yv7h5KqBBQBVihDZYr1gK6KyjQQSoUfwsCyDkCwh5BftIkWzgcTDS74qkGuS258wKAAA=
Waiting for MSG2 encoded as base64.
Tip: use any SPID; we won't be needing it anyway.

Well done! You have proved to be worthy!

Here is the IV || tag || flag encrypted with the SK key and encoded as base64:

rLzc9lIyItQ+oMuuEAXieCYSWEwaIk3CxUTg8vuBk/5Xn8rZ+o5L55YkJatYC/pyXzKaMon0LLELwIw31hdO3s8RU57qRABN1eI=

CTF-BR{SGX_aTt35T4t10N_15_v3Ry_51MpL3_1nD33d!}
[*] Closed connection to enclave.butcher.team port 8088
