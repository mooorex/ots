package OTS

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSign(t *testing.T) {
	params, err := Setup(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	vk, sk, err := params.KeyGen(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("ssssssssss")

	sig, err := sk.Sign(rand.Reader, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !sig.Verify(params, vk, msg) {
		t.Fatalf("emmmm, bug!")
	}
}

func TestVKMarshal(t *testing.T) {
	params, err := Setup(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vk, _, err := params.KeyGen(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	vkm := vk.Marshal()
	vk1, err := new(VerKey).Unmarshal(vkm)
	if err != nil || !bytes.Equal(vk1.Marshal(), vkm) {
		t.Log(vk1.Marshal())
		t.Log(vkm)
		t.Fatalf("emmm, bug")
	}
}

func BenchmarkKeyGen(b *testing.B) {
	params, err := Setup(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		params.KeyGen(rand.Reader)
	}
}

func BenchmarkSign(b *testing.B) {
	params, err := Setup(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	_, sk, err := params.KeyGen(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	msg := []byte("ssssssssss")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sk.Sign(rand.Reader, msg)
	}
}

func BenchmarkVerify(b *testing.B) {
	params, err := Setup(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	vk, sk, err := params.KeyGen(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	msg := []byte("ssssssssss")
	sig, err := sk.Sign(rand.Reader, msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig.Verify(params, vk, msg)
	}
}

func BenchmarkVKMarshal(b *testing.B) {
	params, err := Setup(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	vk, _, err := params.KeyGen(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vk.Marshal()
	}
}
