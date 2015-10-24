// Copyright 2015 Factom Foundation
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package factoid

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/btcsuitereleases/btcutil/base58"
	"runtime/debug"
	"strconv"
	"strings"
)

/*********************************
 * Marshalling helper functions
 *********************************/

func WriteNumber64(out *bytes.Buffer, num uint64) {
	var buf bytes.Buffer

	binary.Write(&buf, binary.BigEndian, num)
	str := hex.EncodeToString(buf.Bytes())
	out.WriteString(str)

}

func WriteNumber32(out *bytes.Buffer, num uint32) {
	var buf bytes.Buffer

	binary.Write(&buf, binary.BigEndian, num)
	str := hex.EncodeToString(buf.Bytes())
	out.WriteString(str)

}

func WriteNumber16(out *bytes.Buffer, num uint16) {
	var buf bytes.Buffer

	binary.Write(&buf, binary.BigEndian, num)
	str := hex.EncodeToString(buf.Bytes())
	out.WriteString(str)

}

func WriteNumber8(out *bytes.Buffer, num uint8) {
	var buf bytes.Buffer

	binary.Write(&buf, binary.BigEndian, num)
	str := hex.EncodeToString(buf.Bytes())
	out.WriteString(str)

}

/**************************************
 * Printing Helper Functions for debugging
 **************************************/

func PrtStk() {
	Prtln()
	debug.PrintStack()
}

func Prt(a ...interface{}) {
	fmt.Print(a...)
}

func Prtln(a ...interface{}) {
	fmt.Println(a...)
}

func PrtData(data []byte) {
	if data == nil || len(data) == 0 {
		fmt.Print("No Data Here")
	} else {
		var nl string = "\n"
		for i, b := range data {
			fmt.Print(nl)
			nl = ""
			fmt.Printf("%2.2X ", int(b))
			if i%32 == 31 {
				nl = "\n"
			} else if i%8 == 7 {
				fmt.Print(" | ")
			}
		}
	}
}
func PrtDataL(title string, data []byte) {
	fmt.Println()
	fmt.Println(title)
	fmt.Print("========================-+-========================-+-========================-+-========================")
	PrtData(data)
	fmt.Println("\n========================-+-========================-+-========================-+-========================")
}

// Does a new line, then indents as specified. DON'T end
// a Print with a CR!
func CR(level int) {
	Prtln()
	PrtIndent(level)
}

func PrtIndent(level int) {
	for i := 0; i < level && i < 10; i++ { // Indent up to 10 levels.
		Prt("    ") //   by printing leading spaces
	}
}

/************************************************
 * Helper Functions for User Address handling
 ************************************************/

// Factoid Address
//
//
// Add a prefix of 0x5fb1 at the start, and the first 4 bytes of a SHA256d to
// the end.  Using zeros for the address, this might look like:
//
//     5fb10000000000000000000000000000000000000000000000000000000000000000d48a8e32
//
// A typical Factoid Address:
//
//     FA1y5ZGuHSLmf2TqNf6hVMkPiNGyQpQDTFJvDLRkKQaoPo4bmbgu
//
// Entry credits only differ by the prefix of 0x592a and typically look like:
//
//     EC3htx3MxKqKTrTMYj4ApWD8T3nYBCQw99veRvH1FLFdjgN6GuNK
//
// More words on this can be found here:
//
// https://github.com/FactomProject/FactomDocs/blob/master/factomDataStructureDetails.md#human-readable-addresses
//

var FactoidPrefix = []byte{0x5f, 0xb1}
var EntryCreditPrefix = []byte{0x59, 0x2a}
var FactoidPrivatePrefix = []byte{0x64, 0x78}
var EntryCreditPrivatePrefix = []byte{0x5d, 0xb6}

// Take fixed point data and produce a nice decimial point
// sort of output that users can handle.
func ConvertDecimal(v uint64) string {
	tv := v / 100000000
	bv := v - (tv * 100000000)
	var str string

	// Count zeros to lop off
	var cnt int
	for cnt = 0; cnt < 7; cnt++ {
		if (bv/10)*10 != bv {
			break
		}
		bv = bv / 10
	}
	// Print the proper format string
	fstr := fmt.Sprintf(" %s%dv.%s0%vd", "%", 12, "%", 8-cnt)
	// Use the format string to print our Factoid balance
	str = fmt.Sprintf(fstr, tv, bv)

	return str
}

// Convert Decimal point input to FixedPoint (no decimal point)
// output suitable for Factom to chew on.
func ConvertFixedPoint(amt string) (string, error) {
	var v int64
	var err error
	index := strings.Index(amt, ".")
	if index == 0 {
		amt = "0" + amt
		index++
	}
	if index < 0 {
		v, err = strconv.ParseInt(amt, 10, 64)
		if err != nil {
			return "", err
		}
		v *= 100000000 // Convert to Factoshis
	} else {
		tp := amt[:index]
		v, err = strconv.ParseInt(tp, 10, 64)
		if err != nil {
			return "", err
		}
		v = v * 100000000 // Convert to Factoshis

		bp := amt[index+1:]
		if len(bp) > 8 {
			bp = bp[:8]
		}
		bpv, err := strconv.ParseInt(bp, 10, 64)
		if err != nil {
			return "", err
		}
		for i := 0; i < 8-len(bp); i++ {
			bpv *= 10
		}
		v += bpv
	}
	return strconv.FormatInt(v, 10), nil
}

//  Convert Factoid and Entry Credit addresses to their more user
//  friendly and human readable formats.
//
//  Creates the binary form.  Just needs the conversion to base58
//  for display.
func ConvertAddressToUser(prefix []byte, addr IAddress) []byte {
	dat := prefix
	dat = append(dat, addr.Bytes()...)
	sha256d := Sha(Sha(dat).Bytes()).Bytes()
	userd := prefix
	userd = append(userd, addr.Bytes()...)
	userd = append(userd, sha256d[:4]...)
	return userd
}

// Convert Factoid Addresses
func ConvertFctAddressToUserStr(addr IAddress) string {
	userd := ConvertAddressToUser(FactoidPrefix, addr)
	return base58.Encode(userd)
}

// Convert Factoid Private Key
func ConvertFctPrivateToUserStr(addr IAddress) string {
	userd := ConvertAddressToUser(FactoidPrivatePrefix, addr)
	return base58.Encode(userd)
}

// Convert Entry Credits
func ConvertECAddressToUserStr(addr IAddress) string {
	userd := ConvertAddressToUser(EntryCreditPrefix, addr)
	return base58.Encode(userd)
}

// Convert Entry Credit Private key
func ConvertECPrivateToUserStr(addr IAddress) string {
	userd := ConvertAddressToUser(EntryCreditPrivatePrefix, addr)
	return base58.Encode(userd)
}

//
// Validates a User representation of a Factom and
// Entry Credit addresses.
//
// Returns false if the length is wrong.
// Returns false if the prefix is wrong.
// Returns false if the checksum is wrong.
//
func validateUserStr(prefix []byte, userFAddr string) bool {
	if len(userFAddr) != 52 {
		return false

	}
	v := base58.Decode(userFAddr)
	if bytes.Compare(prefix, v[:2]) != 0 {
		return false

	}
	sha256d := Sha(Sha(v[:34]).Bytes()).Bytes()
	if bytes.Compare(sha256d[:4], v[34:]) != 0 {
		return false
	}
	return true
}

// Validate Factoids
func ValidateFUserStr(userFAddr string) bool {
	return validateUserStr(FactoidPrefix, userFAddr)
}

// Validate Factoid Private Key
func ValidateFPrivateUserStr(userFAddr string) bool {
	return validateUserStr(FactoidPrivatePrefix, userFAddr)
}

// Validate Entry Credits
func ValidateECUserStr(userFAddr string) bool {
	return validateUserStr(EntryCreditPrefix, userFAddr)
}

// Validate Entry Credit Private Key
func ValidateECPrivateUserStr(userFAddr string) bool {
	return validateUserStr(EntryCreditPrivatePrefix, userFAddr)
}

// Convert a User facing Factoid or Entry Credit address
// or their Private Key representations
// to the regular form.  Note validation must be done
// separately!
func ConvertUserStrToAddress(userFAddr string) []byte {
	v := base58.Decode(userFAddr)
	return v[2:34]
}

func DecodeVarInt(data []byte) (uint64, []byte) {
	return DecodeVarIntGo(data)
}

func EncodeVarInt(out *bytes.Buffer, v uint64) error {
	return EncodeVarIntGo(out, v)
}

// Decode a varaible integer from the given data buffer.
// We use the algorithm used by Go, only BigEndian.
func DecodeVarIntGo(data []byte) (uint64, []byte) {

	var v uint64
	var cnt int
	var b byte
	for cnt, b = range data {
		v = v << 7
		v += uint64(b) & 0x7F
		if b < 0x80 {
			break
		}
	}
	return v, data[cnt+1:]
}

// Encode an integer as a variable int into the given data buffer.
func EncodeVarIntGo(out *bytes.Buffer, v uint64) error {

	if v == 0 {
		out.WriteByte(0)
	}
	h := v
	start := false

	if 0x8000000000000000&h != 0 { // Deal with the high bit set; Zero
		out.WriteByte(0x81) // doesn't need this, only when set.
		start = true        // Going the whole 10 byte path!
	}

	for i := 0; i < 9; i++ {
		b := byte(h >> 56) // Get the top 7 bits
		if b != 0 || start {
			start = true
			if i != 8 {
				b = b | 0x80
			} else {
				b = b & 0x7F
			}
			out.WriteByte(b)
		}
		h = h << 7
	}

	return nil
}

// Decode a variable integer from the given data buffer.
// Returns the uint64 bit value and a data slice positioned
// after the variable integer
func DecodeVarIntBTC(data []byte) (uint64, []byte) {

	b := uint8(data[0])
	if b < 0xfd {
		return uint64(b), data[1:]
	}

	var v uint64

	v = (uint64(data[1]) << 8) | uint64(data[2])
	if b == 0xfd {
		return v, data[3:]
	}

	v = v << 16
	v = v | (uint64(data[3]) << 8) | uint64(data[4])

	if b == 0xfe {
		return v, data[5:]
	}

	v = v << 16
	v = v | (uint64(data[5]) << 8) | uint64(data[6])

	v = v << 16
	v = v | (uint64(data[7]) << 8) | uint64(data[8])

	return v, data[9:]
}

// Encode an integer as a variable int into the given data buffer.
func EncodeVarIntBTC(out *bytes.Buffer, v uint64) error {

	var err error
	switch {
	case v < 0xfd:
		err = out.WriteByte(byte(v))
		if err != nil {
			return err
		}
	case v <= 0xFFFF:
		out.WriteByte(0xfd)
		err = out.WriteByte(byte(v >> 8))
		if err != nil {
			return err
		}
		err = out.WriteByte(byte(v))
		if err != nil {
			return err
		}
	case v <= 0xFFFFFFFF:
		out.WriteByte(0xfe)
		for i := 0; i < 4; i++ {
			v = (v>>24)&0xFF + v<<8
			err = out.WriteByte(byte(v))
			if err != nil {
				return err
			}
		}
	default:
		out.WriteByte(0xff)
		for i := 0; i < 8; i++ {
			v = (v>>56)&0xFF + v<<8
			err = out.WriteByte(byte(v))
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// --------------------------------------------------------
// ------------Wallet Encryption Helper Functions----------
// --------------------------------------------------------

// These functions are used to encrypt and decrypt data
// held in the wallet db files.

//This function takes in a slice of bytes to be encrypted, as well as the 32 byte long
//AES key to encrypt it to.
//It returns the encrypted data.  The encrypted data has an unencrypted random Initialization Vector
//prepended to it (16 bytes).
func EncryptWalletItem(itemToEncrypt []byte, aesKey []byte) (encryptedItem []byte, err error) {
	iv := make([]byte, aes.BlockSize)
	//the IV is a random number to prevent the first bytes of similar Factoid keys
	//encrypted with the same AES key sharing the same first encrypted bytes
	_, err = rand.Read(iv)
	if err != nil {
		return nil, err
	}

	return encryptAesWithIv(itemToEncrypt, aesKey, iv)
}

//This function takes in unencrypted data as well as an initialization vector.
//It also takes in the 256 bit key used to encrypt it.
//it returns the data encrypted with the IV prepended to it.

func encryptAesWithIv(itemToEncrypt []byte, aesKey []byte, iv []byte) (encryptedData []byte, err error) {
	if len(aesKey) != 32 {
		return nil, fmt.Errorf("AES key expected to be 32 bytes long")
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	encryptedData = make([]byte, len(itemToEncrypt)+aes.BlockSize)
	copy(encryptedData, iv)

	aesEncrypter := cipher.NewCFBEncrypter(block, iv[:])
	//encrypt the data but leave the IV in place
	aesEncrypter.XORKeyStream(encryptedData[aes.BlockSize:], itemToEncrypt[:])

	return encryptedData, nil
}

//This function takes in a slice of bytes which was encrypted with the 32 byte long
//AES key, also passed in.  It expects the first 16 bytes to be the unecrypted IV.
//It returns the decrypted data with the IV stripped off.
//This code cannot tell if the decrypting key did not match the encrypting key.
func DecryptWalletItem(itemToDecrypt []byte, aesKey []byte) (decryptedItem []byte, err error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	//check to make sure at least something the size of an IV is prepended
	if len(itemToDecrypt) < aes.BlockSize {
		return nil, fmt.Errorf("Encrypted data is too short.")
	}
	iv := itemToDecrypt[:aes.BlockSize]

	aesDecrypter := cipher.NewCFBDecrypter(block, iv)
	//decrypt in place
	aesDecrypter.XORKeyStream(itemToDecrypt[:], itemToDecrypt[:])
	decryptedItem = make([]byte, (len(itemToDecrypt) - aes.BlockSize))
	//strip off the IV
	copy(decryptedItem, itemToDecrypt[len(iv):])

	return decryptedItem, nil
}
