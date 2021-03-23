package OTS

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"github.com/cloudflare/bn256"
	"io"
	"math/big"
)

//G1 is faster than G2 and GT
type Params struct {
	G *bn256.G1
}

type VerKey struct {
	f *bn256.G1
	h *bn256.G1
	c *bn256.G1
}

type SignKey struct {
	x *big.Int
	y *big.Int
	s *big.Int
	r *big.Int
}

type Signature struct {
	r *big.Int
	s *big.Int
}

////////////////////////////////////

func Setup(r io.Reader) (*Params, error) {
	params := &Params{}
	var err error

	_, params.G, err = bn256.RandomG1(r)
	if err != nil {
		return nil, err
	}

	return params, nil
}

func (params *Params) KeyGen(r io.Reader) (*VerKey, *SignKey, error) {
	var err error
	vk := &VerKey{}
	sk := &SignKey{}

	//select x, y from z^*_p
	sk.x, err = rand.Int(r, new(big.Int).Sub(bn256.Order, big.NewInt(1)))
	if err != nil {
		return nil, nil, err
	}
	sk.x.Add(sk.x, big.NewInt(1))

	sk.y, err = rand.Int(r, new(big.Int).Sub(bn256.Order, big.NewInt(1)))
	if err != nil {
		return nil, nil, err
	}
	sk.y.Add(sk.y, big.NewInt(1))

	//select s, r form z_p
	sk.s, err = rand.Int(r, bn256.Order)
	if err != nil {
		return nil, nil, err
	}

	sk.r, err = rand.Int(r, bn256.Order)
	if err != nil {
		return nil, nil, err
	}

	//compute vk
	vk.f = new(bn256.G1).ScalarMult(params.G, sk.x)
	vk.h = new(bn256.G1).ScalarMult(params.G, sk.y)
	vk.c = new(bn256.G1).ScalarMult(vk.f, sk.r)
	vk.c.Add(vk.c, new(bn256.G1).ScalarMult(vk.h, sk.s))

	return vk, sk, nil
}

func (sk *SignKey) Sign(r io.Reader, m []byte) (*Signature, error) {
	sig := &Signature{}
	var err error

	sig.r, err = rand.Int(r, bn256.Order)
	if err != nil {
		return nil, err
	}

	//[x(r-sig.r)+ys-H(m)]/y
	sig.s = new(big.Int).Sub(sk.r, sig.r)
	sig.s.Mul(sig.s, sk.x)
	sig.s.Sub(sig.s, HashToZp(m))
	sig.s.Mul(sig.s, new(big.Int).ModInverse(sk.y, bn256.Order))
	sig.s.Add(sig.s, sk.s)
	sig.s.Mod(sig.s, bn256.Order)

	return sig, nil
}

func (sig *Signature) Verify(params *Params, vk *VerKey, m []byte) bool {
	//compute g^H(m)f^rh^s
	c := new(bn256.G1).ScalarMult(params.G, HashToZp(m))
	fr := new(bn256.G1).ScalarMult(vk.f, sig.r)
	hs := new(bn256.G1).ScalarMult(vk.h, sig.s)
	c.Add(c, fr)
	c.Add(c, hs)

	return bytes.Equal(c.Marshal(), vk.c.Marshal())
}

func HashToZp(bytestring []byte) *big.Int {
	digest := sha256.Sum256(bytestring)
	bigint := new(big.Int).SetBytes(digest[:])
	bigint.Mod(bigint, bn256.Order)
	return bigint
}
