package wallet

import (
	"encoding/hex"
	"fmt"
	"github.com/FactomProject/factoid"
	"github.com/FactomProject/go-bip32"
	"github.com/FactomProject/go-bip39"
	"github.com/btcsuitereleases/btcutil/base58"
	"strings"
)

func MnemonicStringToPrivateKey(mnemonic string) ([]byte, error) {
	mnemonic = strings.ToLower(strings.TrimSpace(mnemonic))
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, "")
	if err != nil {
		return nil, err
	}

	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, err
	}

	child, err := masterKey.NewChildKey(bip32.FirstHardenedChild + 7)
	if err != nil {
		return nil, err
	}

	return child.Key, nil
}

func MnemonicStringToPrivateKeyString(mnemonic string) (string, error) {
	key, err := MnemonicStringToPrivateKey(mnemonic)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", key), nil
}

func HumanReadableFactoidPrivateKeyToPrivateKey(human string) ([]byte, error) {
	human = strings.TrimSpace(human)
	base, version, err := base58.CheckDecode(human)
	if err != nil {
		return nil, err
	}

	if version != 0x64 || base[0] != 0x78 {
		return nil, fmt.Errorf("Invalid prefix")
	}

	return base[1:], nil
}

func HumanReadableFactoidPrivateKeyToPrivateKeyString(human string) (string, error) {
	key, err := HumanReadableFactoidPrivateKeyToPrivateKey(human)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", key), nil
}

func HumanReadableECPrivateKeyToPrivateKey(human string) ([]byte, error) {
	human = strings.TrimSpace(human)
	base, version, err := base58.CheckDecode(human)
	if err != nil {
		return nil, err
	}

	if version != 0x5d || base[0] != 0xb6 {
		return nil, fmt.Errorf("Invalid prefix")
	}

	return base[1:], nil
}

func HumanReadableECPrivateKeyToPrivateKeyString(human string) (string, error) {
	key, err := HumanReadableECPrivateKeyToPrivateKey(human)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", key), nil
}

/******************************************************************************/
/***************************To public key**************************************/
/******************************************************************************/

func PrivateKeyStringToPublicKeyString(private string) (string, error) {
	pub, err := PrivateKeyStringToPublicKey(private)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", pub), nil
}

func PrivateKeyStringToPublicKey(private string) ([]byte, error) {
	privHex, err := hex.DecodeString(private)
	if err != nil {
		return nil, err
	}
	return PrivateKeyToPublicKey(privHex)
}

func PrivateKeyToPublicKey(private []byte) ([]byte, error) {
	pub, _, err := GenerateKeyFromPrivateKey(private)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

/******************************************************************************/
/****************************To addresses**************************************/
/******************************************************************************/

func PublicKeyStringToFactoidAddressString(public string) (string, error) {
	pubHex, err := hex.DecodeString(public)
	if err != nil {
		return "", err
	}
	add, err := PublicKeyToFactoidAddress(pubHex)
	if err != nil {
		return "", err
	}

	return factoid.ConvertFctAddressToUserStr(add), nil
}

func PublicKeyToFactoidAddress(public []byte) (factoid.IAddress, error) {
	rcd := factoid.NewRCD_1(public)
	add, err := rcd.GetAddress()
	if err != nil {
		return nil, err
	}
	return add, nil
}
