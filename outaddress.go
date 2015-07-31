// Copyright 2015 Factom Foundation
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

// Output object for a factoid transaction.   contains an amount
// and the destination address.

package factoid

type IOutAddress interface {
	ITransAddress
}

type OutAddress struct {
	TransAddress
}

var _ IOutAddress = (*OutAddress)(nil)

func (h *OutAddress) GetHash() IHash {
	panic("Function not implemented")
	return nil
}

func (h *OutAddress) UnmarshalBinaryData(data []byte) ([]byte, error) {
	panic("Function not implemented")
	return nil, nil
}

func (h *OutAddress) UnmarshalBinary(data []byte) error {
	panic("Function not implemented")
	return nil
}

func (b OutAddress) String() string {
	txt, err := b.CustomMarshalText()
	if err != nil {
		return "<error>"
	}
	return string(txt)
}

func (OutAddress) GetDBHash() IHash {
	return Sha([]byte("OutAddress"))
}

func (w1 OutAddress) GetNewInstance() IBlock {
	return new(OutAddress)
}

func (oa OutAddress) GetName() string {
	return "out"
}

func (a OutAddress) CustomMarshalText() (text []byte, err error) {
	return a.CustomMarshalText2("output")
}

/******************************
 * Helper functions
 ******************************/

func NewOutAddress(address IAddress, amount uint64) IOutAddress {
	oa := new(OutAddress)
	oa.amount = amount
	oa.address = address
	return oa
}
