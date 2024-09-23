//go:build !go1.20
// +build !go1.20

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
	"errors"
	"fmt"
)

func (yk *YubiKey) privateKey(slot Slot, public crypto.PublicKey, auth KeyAuth, pp PINPolicy) (crypto.PrivateKey, error) {
	return nil, fmt.Errorf("unsupported public key type: %T", public)
}

func (yk *YubiKey) setPrivateKeyInsecure(private crypto.PrivateKey) ([][]byte, byte, int, error) {
	return nil, 0, 0, errors.New("unsupported private key type")
}

func decodeX25519Public(b []byte) (crypto.PublicKey, error) {
	return nil, fmt.Errorf("unsupported algorithm")
}
