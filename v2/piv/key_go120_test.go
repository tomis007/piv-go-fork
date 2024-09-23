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
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"
)

func TestYubiKeyX25519ImportKey(t *testing.T) {
	importKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("error geneating X25519 key: %v", err)
	}

	yk, close := newTestYubiKey(t)
	defer close()

	slot := SlotAuthentication

	err = yk.SetPrivateKeyInsecure(DefaultManagementKey, slot, importKey, Key{AlgorithmX25519, PINPolicyNever, TouchPolicyNever})
	if err != nil {
		t.Fatalf("error importing key: %v", err)
	}
	want := KeyInfo{
		Algorithm:   AlgorithmX25519,
		PINPolicy:   PINPolicyNever,
		TouchPolicy: TouchPolicyNever,
		Origin:      OriginImported,
		PublicKey:   importKey.Public(),
	}

	got, err := yk.KeyInfo(slot)
	if err != nil {
		t.Fatalf("KeyInfo() = _, %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("KeyInfo() = %#v, want %#v", got, want)
	}
}

func TestYubiKeyX25519SharedKey(t *testing.T) {
	yk, close := newTestYubiKey(t)
	defer close()

	slot := SlotAuthentication

	key := Key{
		Algorithm:   AlgorithmX25519,
		TouchPolicy: TouchPolicyNever,
		PINPolicy:   PINPolicyNever,
	}
	pubKey, err := yk.GenerateKey(DefaultManagementKey, slot, key)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	pub, ok := pubKey.(*ecdh.PublicKey)
	if !ok {
		t.Fatalf("public key is not an ecdh key")
	}
	priv, err := yk.PrivateKey(slot, pub, KeyAuth{})
	if err != nil {
		t.Fatalf("getting private key: %v", err)
	}
	privX25519, ok := priv.(*X25519PrivateKey)
	if !ok {
		t.Fatalf("expected private key to be X25519 private key")
	}

	t.Run("good", func(t *testing.T) {
		peer, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("cannot generate key: %v", err)
		}

		secret1, err := privX25519.SharedKey(peer.PublicKey())
		if err != nil {
			t.Fatalf("key agreement failed: %v", err)
		}
		secret2, err := peer.ECDH(pub)
		if err != nil {
			t.Fatalf("key agreement failed: %v", err)
		}
		if !bytes.Equal(secret1, secret2) {
			t.Errorf("key agreement didn't match")
		}
	})

	t.Run("bad", func(t *testing.T) {
		t.Run("curve", func(t *testing.T) {
			peer, err := ecdh.P256().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("cannot generate key: %v", err)
			}
			_, err = privX25519.SharedKey(peer.PublicKey())
			if !errors.Is(err, errMismatchingAlgorithms) {
				t.Fatalf("unexpected error value: wanted errMismatchingAlgorithms: %v", err)
			}
		})
	})
}
