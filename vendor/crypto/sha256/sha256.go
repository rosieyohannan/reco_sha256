package sha256

// New creates a new, initialised SHA256 digest
func New() [8]uint32 {
	return [8]uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
}

/*----------------------------------------------------
	Message expansion functions
----------------------------------------------------*/

// // rotate right
// func rotateRight(n uint32, count uint) uint32 {
// 	return (n >> count) | (n << (uint(32) - count))
// }

//sigma1(X) = (X right-rotate 17) xor (X right-rotate 19) xor (X right-shift 10)
func mexpSigma1(X uint32) uint32 {
	return (((X >> 17) | (X << 15)) ^ ((X >> 19) | (X << 13)) ^ (X >> 10))
}

//sigma0(X) = (X right-rotate 7) xor (X right-rotate 18) xor (X right-shift 3)
func mexpSigma0(X uint32) uint32 {
	return (((X >> 7) | (X << 25)) ^ ((X >> 18) | (X << 14)) ^ (X >> 3))
}

func mexp(wi2 uint32, wi7 uint32, wi15 uint32, wi16 uint32) uint32 {
	return mexpSigma1(wi2) + wi7 + mexpSigma0(wi15) + wi16
}

/*----------------------------------------------------------------------------
  Round functions
----------------------------------------------------------------------------*/

//maj(X,Y,Z) = (X and Y) xor (X and Z) xor (Y and Z)
func maj(X uint32, Y uint32, Z uint32) uint32 {
	return (X & Y) ^ (X & Z) ^ (Y & Z)
}

//Ch(X,Y,Z) = (X and Y) xor ((not X) and Z)
func ch(X uint32, Y uint32, Z uint32) uint32 {
	return (X & Y) ^ (^X & Z)
}

//Sigma0(X) = (X right-rotate 2) xor (X right-rotate 13) xor (X right-rotate 22)
func sigma0(X uint32) uint32 {
	return (((X >> 2) | (X << 30)) ^ ((X >> 13) | (X << 19)) ^ ((X >> 22) | (X << 10)))
}

//Sigma1(X) = (X right-rotate 6) xor (X right-rotate 11) xor (X right-rotate 25)
func sigma1(X uint32) uint32 {
	return (((X >> 6) | (X << 26)) ^ ((X >> 11) | (X << 21)) ^ ((X >> 25) | (X << 7)))
}

// hash round
func round(k uint32, w uint32, roundIn [8]uint32) [8]uint32 {
	var T1 uint32
	var T2 uint32

	T1 = k + sigma1(roundIn[4]) + ch(roundIn[4], roundIn[5], roundIn[6]) + roundIn[7] + w
	T2 = sigma0(roundIn[0]) + maj(roundIn[0], roundIn[1], roundIn[2])

	return [8]uint32{T1 + T2, roundIn[0], roundIn[1], roundIn[2], roundIn[3] + T1, roundIn[4], roundIn[5], roundIn[6]}
}

/*----------------------------------------------------------------------------
  SHA-256 according to FIPS 180-4 - Byte oriented
----------------------------------------------------------------------------*/

// HashGen - hash calculation from padded message blocks
func HashGen(msgChan <-chan uint32, d [8]uint32, numBlocks uint32, hashChan chan<- [8]uint32) {

	var (
		msgExpBuff [16]uint32 // message expansion buffer 16x32bits
		roundOut   [8]uint32
	)

	k := [64]uint32{0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2}

	// keep reading buffer until end of message
	for i := numBlocks; i != 0; i-- {

		roundOut = d

		// rounds 0 to 15
		for i := 0; i < 16; i++ {
			tempVar := <-msgChan

			msgExpBuff = [16]uint32{msgExpBuff[1], msgExpBuff[2], msgExpBuff[3], msgExpBuff[4], msgExpBuff[5],
				msgExpBuff[6], msgExpBuff[7], msgExpBuff[8], msgExpBuff[9], msgExpBuff[10],
				msgExpBuff[11], msgExpBuff[12], msgExpBuff[13], msgExpBuff[14], msgExpBuff[15], tempVar}

			roundOut = round(k[i], msgExpBuff[15], roundOut)
		}

		// rounds 16 to 63
		for j := 16; j < 64; j++ {
			fdbk := mexp(msgExpBuff[14], msgExpBuff[9], msgExpBuff[1], msgExpBuff[0])

			msgExpBuff = [16]uint32{msgExpBuff[1], msgExpBuff[2], msgExpBuff[3], msgExpBuff[4], msgExpBuff[5],
				msgExpBuff[6], msgExpBuff[7], msgExpBuff[8], msgExpBuff[9], msgExpBuff[10],
				msgExpBuff[11], msgExpBuff[12], msgExpBuff[13], msgExpBuff[14], msgExpBuff[15], fdbk}

			roundOut = round(k[j], msgExpBuff[15], roundOut)
		}

		//Update digest after round 63 has finished
		d[0] = roundOut[0] + d[0]
		d[1] = roundOut[1] + d[1]
		d[2] = roundOut[2] + d[2]
		d[3] = roundOut[3] + d[3]
		d[4] = roundOut[4] + d[4]
		d[5] = roundOut[5] + d[5]
		d[6] = roundOut[6] + d[6]
		d[7] = roundOut[7] + d[7]

	} // end of padded message blocks

	hashChan <- d

}
