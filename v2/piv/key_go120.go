//go:build go1.20
// +build go1.20

// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package piv

import (
	"crypto"
	"crypto/ecdh"
	"fmt"
)

type X25519PrivateKey struct {
	yk   *YubiKey
	slot Slot
	pub  *ecdh.PublicKey
	auth KeyAuth
	pp   PINPolicy
}

func (k *X25519PrivateKey) Public() crypto.PublicKey {
	return k.pub
}

// SharedKey performs an ECDH exchange and returns the shared secret.
//
// Peer's public key must use the same algorithm as the key in this slot, or an
// error will be returned.
func (k *X25519PrivateKey) SharedKey(peer *ecdh.PublicKey) ([]byte, error) {
	return k.auth.do(k.yk, k.pp, func(tx *scTx) ([]byte, error) {
		return ykECDHX25519(tx, k.slot, k.pub, peer)
	})
}

func (yk *YubiKey) tryX25519PrivateKey(slot Slot, public crypto.PublicKey, auth KeyAuth, pp PINPolicy) (crypto.PrivateKey, error) {
	switch pub := public.(type) {
	case *ecdh.PublicKey:
		if crv := pub.Curve(); crv != ecdh.X25519() {
			return nil, fmt.Errorf("unsupported ecdh curve: %v", crv)
		}
		return &X25519PrivateKey{yk, slot, pub, auth, pp}, nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", public)
	}
}

func (yk *YubiKey) tryX22519PrivateKeyInsecure(private crypto.PrivateKey) ([][]byte, byte, int, error) {
	switch priv := private.(type) {
	case *ecdh.PrivateKey:
		if crv := priv.Curve(); crv != ecdh.X25519() {
			return nil, 0, 0, fmt.Errorf("unsupported ecdh curve: %v", crv)
		}
		// seed
		params := make([][]byte, 0)
		params = append(params, priv.Bytes())
		return params, 0x08, 32, nil
	default:
		return nil, 0, 0, fmt.Errorf("unsupported private key type: %T", private)
	}
}

func decodeX25519Public(b []byte) (*ecdh.PublicKey, error) {
	// Adaptation of
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=95
	p, _, err := unmarshalASN1(b, 2, 0x06)
	if err != nil {
		return nil, fmt.Errorf("unmarshal points: %v", err)
	}
	return ecdh.X25519().NewPublicKey(p)
}

func ykECDHX25519(tx *scTx, slot Slot, pub *ecdh.PublicKey, peer *ecdh.PublicKey) ([]byte, error) {
	if crv := pub.Curve(); crv != ecdh.X25519() {
		return nil, fmt.Errorf("unsupported ecdh curve: %v", crv)
	}
	if pub.Curve() != peer.Curve() {
		return nil, errMismatchingAlgorithms
	}
	cmd := apdu{
		instruction: insAuthenticate,
		param1:      algX25519,
		param2:      byte(slot.Key),
		data: marshalASN1(0x7c,
			append([]byte{0x82, 0x00},
				marshalASN1(0x85, peer.Bytes())...)),
	}
	resp, err := tx.Transmit(cmd)
	if err != nil {
		return nil, fmt.Errorf("command failed: %w", err)
	}

	sig, _, err := unmarshalASN1(resp, 1, 0x1c) // 0x7c
	if err != nil {
		return nil, fmt.Errorf("unmarshal response: %v", err)
	}
	sharedSecret, _, err := unmarshalASN1(sig, 2, 0x02) // 0x82
	if err != nil {
		return nil, fmt.Errorf("unmarshal response signature: %v", err)
	}

	return sharedSecret, nil
}
