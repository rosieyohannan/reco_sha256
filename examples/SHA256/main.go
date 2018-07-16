/*----------------------------------
  Example kernel code for SHA256
----------------------------------*/

package main

import (
	// import the entire framework (including bundled verilog)
	_ "github.com/ReconfigureIO/sdaccel"

	"github.com/rosieyohannan/crypto/sha256"
	// Use the new SMI protocol package
	"github.com/ReconfigureIO/sdaccel/smi"
)

// Top level of kernel
func Top(
	numBlocks uint32,
	inputBuff uintptr,
	outputBuff uintptr,
	// smi ports
	readReq chan<- smi.Flit64,
	readResp <-chan smi.Flit64,
	writeReq chan<- smi.Flit64,
	writeResp <-chan smi.Flit64) {

	msgChan := make(chan uint32, 16)
	hashChan := make(chan [8]uint32, 1)
	outChan := make(chan uint32, 8)

	// create a new digest
	d := sha256.New()

	// calculate number of 32bit xfers required
	num32s := numBlocks << 4

	// xfer from input buffer to blksChan
	go smi.ReadBurstUInt32(readReq, readResp, inputBuff, smi.DefaultOptions, num32s, msgChan)

	// calculate hash over all blocks
	go sha256.HashGen(msgChan, d, numBlocks, hashChan)

	// break 256bit hash into 8 seperate 32bit words
	go func() {
		tempVar := <-hashChan
		for i := 0; i < 8; i++ {
			outChan <- tempVar[i]
		}
	}()

	// write hash back to output buffer
	go smi.WriteBurstUInt32(writeReq, writeResp, outputBuff, smi.DefaultOptions, 8, outChan)

}
