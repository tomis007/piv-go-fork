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

import "testing"

func TestYubiKeyX25519Legacy(t *testing.T) {
	yk, close := newTestYubiKey(t)
	defer close()

	slot := SlotAuthentication

	key := Key{
		Algorithm:   AlgorithmX25519,
		TouchPolicy: TouchPolicyNever,
		PINPolicy:   PINPolicyNever,
	}
	_, err := yk.GenerateKey(DefaultManagementKey, slot, key)
	if err == nil {
		t.Error("expected error with legacy Go")
	}

	importKey := []byte{
		0x6b, 0x66, 0x8f, 0xbe, 0xad, 0x61, 0x9d, 0x9f,
		0xb5, 0x4b, 0x14, 0xa7, 0x34, 0x03, 0xb7, 0x21,
		0xde, 0x9a, 0x0c, 0xa4, 0x79, 0x83, 0x2c, 0xee,
		0x76, 0x78, 0xe1, 0x9c, 0xe3, 0x06, 0xa7, 0x38,
	}
	err = yk.SetPrivateKeyInsecure(DefaultManagementKey, slot, importKey, Key{AlgorithmX25519, PINPolicyNever, TouchPolicyNever})
	if err == nil {
		t.Error("expected error with legacy Go")
	}
}
