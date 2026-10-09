package gost34112012

import (
	"bytes"
	"encoding/binary"
	"errors"

	"gitverse.ru/uzer_007/gogost/v3/internal/errx"
)

const MarshalledName = "STREEBOG"

func (h *Hash) MarshalBinary() (data []byte, err error) {
	data = make([]byte, len(MarshalledName)+1+8+2*BlockSize+h.bufLen)
	copy(data, []byte(MarshalledName))
	idx := len(MarshalledName)
	data[idx] = byte(h.size)
	idx += 1
	binary.BigEndian.PutUint64(data[idx:idx+8], h.n)
	idx += 8
	copy(data[idx:], h.hsh[:])
	idx += BlockSize
	copy(data[idx:], h.chk[:])
	idx += BlockSize
	copy(data[idx:], h.buf[:h.bufLen])
	return
}

func (h *Hash) UnmarshalBinary(data []byte) error {
	expectedLen := len(MarshalledName) + 1 + 8 + 2*BlockSize
	if len(data) < expectedLen {
		return errors.New("gogost/internal/gost34112012: длина данных " + errx.Int(len(data)) + ", ожидалось " + errx.Int(expectedLen))
	}
	if !bytes.HasPrefix(data, []byte(MarshalledName)) {
		return errors.New("gogost/internal/gost34112012: Нет префикса имени хеша")
	}
	idx := len(MarshalledName)
	h.size = int(data[idx])
	idx += 1
	h.n = binary.BigEndian.Uint64(data[idx : idx+8])
	idx += 8
	copy(h.hsh[:], data[idx:])
	idx += BlockSize
	copy(h.chk[:], data[idx:])
	idx += BlockSize
	h.bufLen = copy(h.buf[:], data[idx:])
	return nil
}
