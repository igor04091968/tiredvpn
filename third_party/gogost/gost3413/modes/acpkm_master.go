package modes

import "errors"

// DeriveACPKMMasterInto derives consecutive 32-byte section keys from a
// 32-byte master key according to RFC 8645 section 6.3.1. masterFrequency
// is T* in bytes and must be a multiple of 32 and the cipher block size.
// dst must contain an integral number of section keys. The caller chooses
// the data-section size of its protocol separately.
func DeriveACPKMMasterInto(dst, masterKey []byte, algorithm Algorithm, masterFrequency int) error {
	if len(masterKey) != 32 || len(dst) == 0 || len(dst)%32 != 0 || masterFrequency < 32 || masterFrequency%32 != 0 {
		return errors.New("gogost/modes: invalid ACPKM-Master parameters")
	}
	var stream *CTRACPKM
	var err error
	switch algorithm {
	case AlgorithmKuznechik:
		var cipher *Kuznechik
		cipher, err = NewKuznechik(masterKey)
		if err == nil {
			stream, err = cipher.CTRACPKM([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, masterFrequency)
		}
	case AlgorithmMagma:
		var cipher *Magma
		cipher, err = NewMagma(masterKey)
		if err == nil {
			stream, err = cipher.CTRACPKM([]byte{0xff, 0xff, 0xff, 0xff}, masterFrequency)
		}
	default:
		return errors.New("gogost/modes: unsupported ACPKM-Master cipher")
	}
	if err != nil {
		return err
	}
	defer stream.Close()
	clear(dst)
	_, err = stream.XORKeyStreamTo(dst, dst)
	return err
}
