// Copyright 2015 Factom Foundation
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

// This is a minimum wallet to be used to test the coin
// There isn't much in the way of interest in security
// here, but rather provides a mechanism to create keys
// and sign transactions, etc.

package wallet

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	fct "github.com/FactomProject/factoid"
	"crypto/subtle"
)

type IWalletEntry interface {
	fct.IBlock
	// Set the RCD for this entry.  USE WITH CAUTION!  You change
	// the hash and thus the address returned by the wallet entry!
	SetRCD(fct.IRCD)
	// Get the RCD used to validate an input
	GetRCD() fct.IRCD
	// Add a public and private key.  USE WITH CAUTION! You change
	// the hash and thus the address returned by the wallet entry!
	AddKey(public, private []byte)
	// Add a public and private key, but encrypt it
	AddEncKey(public, private []byte, aesKey []byte)
	// Get the name for this address
	GetName() []byte
	// Get the Public Key by its index
	GetKey(i int) []byte
	// Get the Private Key by its index and supply the key to decrypt it
	GetEncPrivKey(i int, aesKey []byte) []byte
	// Get the Private Key, but assume no encryption
	GetPrivKey(i int) []byte
	// Set the name for this address
	SetName([]byte)
	// Get the address defined by the RCD for this wallet entry.
	GetAddress() (fct.IAddress, error)
	// Return "ec" for Entry Credit address, and "fct" for a Factoid address
	GetType() string
	SetType(string)
}

type WalletEntry struct {
	// Type string for the address.  Either "ec" or "fct"
	addrtype string
	// 2 byte length not included here
	name []byte
	rcd  fct.IRCD // Verification block for this IWalletEntry
	// 1 byte count of public keys
	public [][]byte // Set of public keys necessary towe sign the rcd
	// 1 byte count of private keys
	private [][]byte // Set of private keys necessary to sign the rcd
}

var _ IWalletEntry = (*WalletEntry)(nil)

/*************************************
 *       Stubs
 *************************************/

func (b WalletEntry) GetHash() fct.IHash {
	return nil
}

/***************************************
 *       Methods
 ***************************************/

func (w WalletEntry) GetName() []byte {
	return w.name
}

func (w WalletEntry) GetType() string {
	return w.addrtype
}

func (w *WalletEntry) SetType(addrtype string) {
	switch addrtype {
	case "ec":
		fallthrough
	case "fct":
		w.addrtype = addrtype
	default:
		panic("Invalid type passed to SetType()")
	}
}

func (b WalletEntry) String() string {
	txt, err := b.CustomMarshalText()
	if err != nil {
		return "<error>"
	}
	return string(txt)
}

func (w1 WalletEntry) GetAddress() (fct.IAddress, error) {
	if w1.rcd == nil {
		return nil, fmt.Errorf("Should never happen. Missing the rcd block")
	}
	var adr fct.IHash
	var err error
	if w1.addrtype == "fct" {
		adr, err = w1.rcd.GetAddress()
	} else {
		if len(w1.public) == 0 {
			err = fmt.Errorf("No Public Key for WalletEntry")
		} else {
			adr = fct.NewHash(w1.public[0])
		}
	}
	if err != nil {
		return nil, err
	}
	return adr, nil
}

func (w1 WalletEntry) GetDBHash() fct.IHash {
	return fct.Sha([]byte("WalletEntry"))
}

func (WalletEntry) GetNewInstance() fct.IBlock {
	return new(WalletEntry)
}

func (w1 *WalletEntry) IsEqual(w fct.IBlock) []fct.IBlock {
	w2, ok := w.(*WalletEntry)
	if !ok || w1.GetType() != w2.GetType() {
		r := make([]fct.IBlock, 0, 3)
		return append(r, w1)
	}

	if 0 != bytes.Compare(w1.name, w2.name) {
		r := make([]fct.IBlock, 0, 3)
		return append(r, w1)
	}

	if nil != w1.rcd.IsEqual(w2.rcd) {
		r := make([]fct.IBlock, 0, 3)
		return append(r, w1)
	}

	for i, public := range w1.public {
		if bytes.Compare(w2.public[i], public) != 0 {
			r := make([]fct.IBlock, 0, 3)
			return append(r, w1)
		}
	}
	for i, private := range w1.private {
		if bytes.Compare(w2.private[i], private) != 0 {
			r := make([]fct.IBlock, 0, 3)
			return append(r, w1)
		}
	}
	
	return nil
}

func (w *WalletEntry) UnmarshalBinaryData(data []byte) ([]byte, error) {

	// handle the type byte
	if uint(data[0]) > 1 {
		return nil, fmt.Errorf("Invalid type byte")
	}
	if data[0] == 0 {
		w.addrtype = "fct"
	} else {
		w.addrtype = "ec"
	}
	data = data[1:]

	len, data := binary.BigEndian.Uint16(data[0:2]), data[2:]
	n := make([]byte, len, len) // build a place for the name
	copy(n, data[:len])         // copy it into that place
	data = data[len:]           // update data pointer
	w.name = n                  // Finally!  set the name

	if w.rcd == nil {
		w.rcd = fct.CreateRCD(data) // looks ahead, and creates the right RCD
	}
	data, err := w.rcd.UnmarshalBinaryData(data)
	if err != nil {
		return nil, err
	}

	blen, data := data[0], data[1:]
	w.public = make([][]byte, blen, blen)
	for i := 0; i < int(blen); i++ {
		w.public[i] = make([]byte, fct.ADDRESS_LENGTH, fct.ADDRESS_LENGTH)
		copy(w.public[i], data[:fct.ADDRESS_LENGTH])
		data = data[fct.ADDRESS_LENGTH:]
	}

	blen, data = data[0], data[1:]
	w.private = make([][]byte, blen, blen)
	for i := 0; i < int(blen); i++ {
		keylen, data := data[0], data[1:]
		w.private[i] = make([]byte, keylen, keylen)
		copy(w.private[i], data[:keylen])
		data = data[keylen:]
	}
	return data, nil
}

func (w *WalletEntry) UnmarshalBinary(data []byte) error {
	_, err := w.UnmarshalBinaryData(data)
	return err
}

func (w WalletEntry) MarshalBinary() ([]byte, error) {
	var out bytes.Buffer

	if w.addrtype == "fct" {
		out.WriteByte(0)
	} else if w.addrtype == "ec" {
		out.WriteByte(1)
	} else {
		panic("Address type not set")
	}

	binary.Write(&out, binary.BigEndian, uint16(len([]byte(w.name))))
	out.Write([]byte(w.name))
	data, err := w.rcd.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out.Write(data)
	out.WriteByte(byte(len(w.public)))
	for _, public := range w.public {
		out.Write(public)
	}
	out.WriteByte(byte(len(w.private)))
	for _, private := range w.private {
		out.WriteByte(byte(len(private)))
		out.Write(private)
	}
	return out.Bytes(), nil
}

func (w WalletEntry) CustomMarshalText() (text []byte, err error) {
	var out bytes.Buffer

	out.WriteString("name:  ")
	out.Write(w.name)
	out.WriteString("\n factoid address:")
	hash, err := w.rcd.GetAddress()
	out.WriteString(hash.String())
	out.WriteString("\n")

	out.WriteString("\n public:  ")
	for i, public := range w.public {
		fct.WriteNumber16(&out, uint16(i))
		out.WriteString(" ")
		addr := hex.EncodeToString(public)
		out.WriteString(addr)
		out.WriteString("\n")
	}

	out.WriteString("\n private:  ")
	for i, private := range w.private {
		fct.WriteNumber16(&out, uint16(i))
		out.WriteString(" ")
		addr := hex.EncodeToString(private)
		out.WriteString(addr)
		out.WriteString("\n")
	}

	return out.Bytes(), nil
}

func (w *WalletEntry) SetRCD(rcd fct.IRCD) {
	w.rcd = rcd
}

func (w WalletEntry) GetRCD() fct.IRCD {
	return w.rcd
}

func (w *WalletEntry) AddEncKey(public, private []byte, aesKey []byte) {
	if len(public) != fct.ADDRESS_LENGTH || (len(private) != fct.ADDRESS_LENGTH &&
		                    len(private) != fct.PRIVATE_LENGTH) {
		panic(fmt.Sprintf("Bad Keys presented to AddKey.  Should not happen."+
		 "\n  public: %x\n  private: %x", public, private))
	}
	pu := make([]byte, fct.ADDRESS_LENGTH, fct.ADDRESS_LENGTH)
	pr := make([]byte, fct.PRIVATE_LENGTH, fct.PRIVATE_LENGTH)
	copy(pu, public)
	copy(pr[:32], private)
	copy(pr[32:], public)
	w.public = append(w.public, pu)
	w.rcd = fct.NewRCD_1(pu)

	// Check to see if the aes key passed in is 32 bytes of zeros. 
	// If so, we will treat the private key as not being encrypted.
	if (1 == subtle.ConstantTimeCompare(aesKey, fct.ZERO_HASH)){  //unencrypted
		w.private = append(w.private, pr)
	}else{ //encryption key given
		encryptedKey, err := fct.EncryptWalletItem(pr, aesKey)
		if nil != err{
			panic(err)
		}
		w.private = append(w.private, encryptedKey)
	}
}

// Add a key and disregard encryption
func (w *WalletEntry) AddKey(public, private []byte) {
	w.AddEncKey(public, private, fct.ZERO_HASH)
}

func (we *WalletEntry) GetKey(i int) []byte {
	return we.public[i]
}

func (we *WalletEntry) GetEncPrivKey(i int, aesKey []byte) []byte {
	// Check to see if the aes key passed in is a 32 bytes of zeros. 
	// If so, we will treat the private key as not being encrypted.
	if (1 == subtle.ConstantTimeCompare(aesKey, fct.ZERO_HASH)){  //unencrypted
		return we.private[i]
	}else{  //encryption key given
		decryptedKey, err := fct.DecryptWalletItem(we.private[i], aesKey)
		if nil != err{
			panic(err)
		}
		return decryptedKey
	}
}

func (we *WalletEntry) GetPrivKey(i int) []byte {
	return we.GetEncPrivKey(i, fct.ZERO_HASH)
}

func (w *WalletEntry) SetName(name []byte) {
	w.name = name
}
