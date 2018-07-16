/*--------------------------------------------
 SHA256 test code
 Emulates Host & kernel
---------------------------------------------*/

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"testing"

	"github.com/rosieyohannan/crypto/sha256"
	"github.com/rosieyohannan/crypto/sha256/host"
)

func TestMain(t *testing.T) {

	var (
		inData uint32
	)

	// channels
	msgChan := make(chan uint32, 16)
	hashChan := make(chan [8]uint32, 1)
	outChan := make(chan uint32, 8)
	defer close(msgChan)
	defer close(hashChan)
	defer close(outChan)

	fmt.Println("------- SHA256 TEST -------")

	wg := new(sync.WaitGroup)
	wg.Add(4)

	/*---------------------------------------------
			EMULATE HOST
			- Pad message, calculate number of 64byte blocks
			- Set up input & output buffers
	---------------------------------------------*/

	// Pad message & calculate number of 64byte blocks
	msg := []byte("Tomorrow, and tomorrow, and tomorrow, Creeps in this petty pace from day to day, To the last syllable of recorded time; And all our yesterdays have lighted fools	The way to dusty death.")
	msg = host.Pad(msg)
	msgSize := binary.Size(msg)
	numBlocks := uint32(msgSize >> 6)
	// initialize input & output memory buffers
	inputBuff := bytes.NewBuffer(msg)
	outputBuff := new(bytes.Buffer)

	fmt.Println("Number of blocks in padded message: ", numBlocks)

	/*---------------------------------------------
	    EMULATE KERNEL
	---------------------------------------------*/
	// create a new digest
	d := sha256.New()

	// calculate number of 32bit xfers required
	num32s := numBlocks << 4

	// emulate ReadBurstUInt32 xfers from input buffer to message channel
	go func() {
		defer wg.Done()
		for i := 0; i < int(num32s); i++ {
			binary.Read(inputBuff, binary.BigEndian, &inData)
			msgChan <- inData
		}
	}()

	// calculate hash over all blocks
	go func() {
		defer wg.Done()
		sha256.HashGen(msgChan, d, numBlocks, hashChan)
	}()

	// break 256bit hash into 8 seperate 32bit words
	go func() {
		defer wg.Done()
		tempVar := <-hashChan
		for i := 0; i < 8; i++ {
			outChan <- tempVar[i]
		}
	}()

	// emulate WriteBurstUInt32 xfer to output buffer
	go func() {
		defer wg.Done()
		for i := 0; i < 8; i++ {
			tempVar := <-outChan
			err := binary.Write(outputBuff, binary.BigEndian, tempVar)
			if err != nil {
				log.Panic(err)
			}
		}
	}()

	/*---------------------------------------------
	    EMULATE HOST
	---------------------------------------------*/

	// wait for "kernel" to finish
	wg.Wait()

	ret := make([]byte, 32)
	err := binary.Read(outputBuff, binary.LittleEndian, &ret) // outputBuffer -> ret
	if err != nil {
		log.Fatal("binary.Read failed:", err)
	}

	s := hex.EncodeToString(ret)

	if s != "7b965f81513be39e186f6c595a7bec3d668a255b025681e138394c5e51645668" {
		log.Fatalf("%s != %s", s, "7b965f81513be39e186f6c595a7bec3d668a255b025681e138394c5e51645668")
	} else {
		log.Printf("Got hex string of %s", s)
	}

	fmt.Println("------- TEST FINISHED -------")

}
