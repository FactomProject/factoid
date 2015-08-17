// Copyright 2015 Factom Foundation
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package factoid

import (
	"bytes"
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

// Converts factoshis to floating point factoids
func ConvertDecimalToFloat(v uint64) float64 {
	f := float64(v)
	f = f / 100000000.0
	return f
}

// Converts factoshis to floating point string
func ConvertDecimalToString(v uint64) string {
	f := ConvertDecimalToFloat(v)
	return fmt.Sprintf("%.8f", f)
}

// Take fixed point data and produce a nice decimial point
// sort of output that users can handle.
func ConvertDecimalToPaddedString(v uint64) string {
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
	sha256d := Sha(Sha(addr.Bytes()).Bytes()).Bytes()
	userd := make([]byte, 0, 32)
	userd = append(userd, prefix...)
	userd = append(userd, addr.Bytes()...)
	userd = append(userd, sha256d[:4]...)
	return userd
}

// Convert Factoid Addresses
func ConvertFctAddressToUserStr(addr IAddress) string {
	userd := ConvertAddressToUser(FactoidPrefix, addr)
	return base58.Encode(userd)
}

// Convert Entry Credits
func ConvertECAddressToUserStr(addr IAddress) string {
	userd := ConvertAddressToUser(EntryCreditPrefix, addr)
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
	sha256d := Sha(Sha(v[2:34]).Bytes()).Bytes()
	if bytes.Compare(sha256d[:4], v[34:]) != 0 {
		return false
	}
	return true
}

// Validate Factoids
func ValidateFUserStr(userFAddr string) bool {
	return validateUserStr(FactoidPrefix, userFAddr)
}

// Validate Entry Credits
func ValidateECUserStr(userFAddr string) bool {
	return validateUserStr(EntryCreditPrefix, userFAddr)
}

// Convert a User facing Factoid or Entry Credit address
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
