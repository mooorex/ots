package OTS

import (
	"errors"
	"github.com/cloudflare/bn256"
)

// the marshalled value size of a G1 element is numbytes*2
// the marshalled value size of a G2 element is 1+numbytes*4, the first byte is 0x01 if it the element is not infinity, 0x00 otherwise.
// the marshalled value size of a GT element is numbytes*12

const (
	numBytes = 256 / 8     //32
	nbShift  = 5           //1<<5 = 32
	G1Count  = 1 << 1      //g1： *2
	G2Count  = 1 << 2      //g2:  *4
	GTCount  = 1<<2 + 1<<3 //gt:  *12
)

//gcount: one of G*Count
func getSlice(b []byte, gcount, offset uint) []byte {
	return b[offset<<nbShift : (offset+gcount)<<nbShift]
}

///////////////////////////

func (vk *VerKey) Marshal() []byte {
	count := 3 * G1Count
	ret := make([]byte, count<<nbShift)
	copy(getSlice(ret, G1Count, 0), vk.f.Marshal())
	copy(getSlice(ret, G1Count, G1Count), vk.h.Marshal())
	copy(getSlice(ret, G1Count, 2*G1Count), vk.c.Marshal())

	return ret
}

func (vk *VerKey) Unmarshal(ret []byte) (*VerKey, error) {
	count := 3 * G1Count
	if len(ret) != count<<nbShift {
		return nil, errors.New("invalid parameters")
	}

	vk.f = new(bn256.G1)
	_, err := vk.f.Unmarshal(getSlice(ret, G1Count, 0))
	if err != nil {
		return nil, err
	}

	vk.h = new(bn256.G1)
	_, err = vk.h.Unmarshal(getSlice(ret, G1Count, G1Count))
	if err != nil {
		return nil, err
	}

	vk.c = new(bn256.G1)
	_, err = vk.c.Unmarshal(getSlice(ret, G1Count, 2*G1Count))
	if err != nil {
		return nil, err
	}

	return vk, nil
}
