// Copyright 2015 Factom Foundation
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

// Transaction Address for a factoid transaction.   contains an amount
// and the address.  Our inputs spec how much is going into a transaction
// and our outputs spec how much is going out of a transaction.  This
// avoids having to have extra outputs to deal with change.
//

package factoid

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
)

type ITransAddress interface {
	IBlock
	GetAmount() uint64
	SetAmount(uint64)
	GetAddress() IAddress
	SetAddress(IAddress)
	CustomMarshalText2(string) ([]byte, error)
}

type TransAddress struct {
	amount  uint64
	address IAddress
}

var _ ITransAddress = (*TransAddress)(nil)

func (h *TransAddress) GetDBHash() IHash {
	panic("Function not implemented")
	return nil
}

func (h *TransAddress) GetHash() IHash {
	panic("Function not implemented")
	return nil
}

func (h *TransAddress) GetNewInstance() IBlock {
	panic("Function not implemented")
	return nil
}

func (h *TransAddress) UnmarshalBinary(data []byte) error {
	panic("Function not implemented")
	return nil
}

func (h *TransAddress) String() string {
	panic("Function not implemented")
	return ""
}

func (t *TransAddress) IsEqual(addr IBlock) []IBlock {
	a, ok := addr.(ITransAddress)
	if !ok || // Not the right kind of IBlock
		a.GetAmount() != t.GetAmount() {
		r := make([]IBlock, 0, 5)
		return append(r, t)
	} // Amount is different
	r := a.GetAddress().IsEqual(t.GetAddress()) // Address is different
	if r != nil {
		return append(r, t)
	}
	return nil
}

func (t *TransAddress) UnmarshalBinaryData(data []byte) (newData []byte, err error) {

	if len(data) < 36 {
		return nil, fmt.Errorf("Data source too short to UnmarshalBinary() an address: %d", len(data))
	}

	t.amount, data = DecodeVarInt(data)
	t.address = new(Address)

	data, err = t.address.UnmarshalBinaryData(data)

	return data, err
}

// MarshalBinary.  'nuff said
func (a TransAddress) MarshalBinary() ([]byte, error) {
	var out bytes.Buffer

	err := EncodeVarInt(&out, a.amount)
	if err != nil {
		return nil, err
	}
	data, err := a.address.MarshalBinary()
	out.Write(data)

	return out.Bytes(), err
}

// Accessor. Default to a zero length string.  This is a debug
// thing for looking out what we have built. Used by
// CustomMarshalText
func (ta TransAddress) GetName() string {
	return ""
}

// Accessor.  Get the amount with this address.
func (ta TransAddress) GetAmount() uint64 {
	return ta.amount
}

// Accessor.  Get the amount with this address.
func (ta *TransAddress) SetAmount(amount uint64) {
	ta.amount = amount
}

// Accessor.  Get the raw address.  Could be an actual address,
// or a hash of an authorization block.  See authorization.go
func (ta TransAddress) GetAddress() IAddress {
	return ta.address
}

// Accessor.  Get the raw address.  Could be an actual address,
// or a hash of an authorization block.  See authorization.go
func (ta *TransAddress) SetAddress(address IAddress) {
	ta.address = address
}

func (ta TransAddress) CustomMarshalText() ([]byte, error) {
	return ta.CustomMarshalText2("")
}

// Make this into somewhat readable text.
func (ta TransAddress) CustomMarshalText2(label string) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString(fmt.Sprintf("   %8s:", label))
	v := ConvertDecimal(ta.amount)
	fill := 8 - len(v) + strings.Index(v, ".") + 1
	fstr := fmt.Sprintf("%%%vs%%%vs ", 18-fill, fill)
	out.WriteString(fmt.Sprintf(fstr, v, ""))
	out.WriteString(ConvertFctAddressToUserStr(ta.address))
	str := fmt.Sprintf("\n                  %016x %038s\n\n", ta.amount, string(hex.EncodeToString(ta.GetAddress().Bytes())))
	out.WriteString(str)
	return out.Bytes(), nil
}
