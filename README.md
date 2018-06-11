SHA256 for ReconfigureIO
-----------------------------

This is an implementation of the FIPS 180-4 SHA256 hashing algorithm written in Go and intended for use with ReconfigureIO tools.
It uses the SMI protocol for memory communication.

vendor/crypto/sha256.go
- A package that contains the functions necessary to implement a SHA256 hash generator.  The main function is 'HashGen' which iterates over all the 512bit blocks of the input message which 
it reads from the msgChan channel and outputs a 256 hash (or digest) to the hashChan channel.

vendor/crypto/host/padsha256.go
 - A padding function design to be run on the host. It will pad the message according to FIPS 180-4 such that its length is and integer multiple of 512bits.

cmd/test-sha256/main.go
- An example host code.

main.go
 - An example kernel code.
 
main_test.go
 - A go test file that was used to emulate the functionality of both host and kernel for initial prototyping and debugging.


 Possible modifications
  - the main loop of 64 rounds in the 'HashGen' function could be unrolled partially or completely to imprve performance at the cost of extra resources.

