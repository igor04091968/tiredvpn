package cms_test

import (
	"testing"

	"gitverse.ru/uzer_007/gogost/v3/cms"
)

func FuzzCMSParsers(f *testing.F) {
	for _, seed := range [][]byte{
		nil,
		{0x30, 0x00},
		{0x30, 0x80, 0, 0},
		{0x30, 0x80, 0x24, 0x80, 0x04, 0x00, 0, 0, 0, 0},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = cms.ParseSignedData(input)
		_, _ = cms.ParseEnvelopedData(input)
	})
}
