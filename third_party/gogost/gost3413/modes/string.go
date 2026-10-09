package modes

import "strings"

func (a Algorithm) String() string {
	switch a {
	case AlgorithmGOST28147:
		return "gost28147"
	case AlgorithmMagma:
		return "magma"
	case AlgorithmKuznechik:
		return "kuznechik"
	default:
		return "unknown"
	}
}

func ParseAlgorithm(s string) (Algorithm, error) {
	switch normalizeName(s) {
	case "gost28147", "gost2814789", "gost2814789crypto", "28147":
		return AlgorithmGOST28147, nil
	case "magma", "gost341264", "gost3412magma", "gost3412642015":
		return AlgorithmMagma, nil
	case "kuznechik", "grasshopper", "gost3412128", "gost3412kuznechik", "gost34121282015":
		return AlgorithmKuznechik, nil
	default:
		return AlgorithmUnknown, ErrInvalidAlgorithm
	}
}

func (m Mode) String() string {
	switch m {
	case ModeECB:
		return "ecb"
	case ModeCBC:
		return "cbc"
	case ModeCFB:
		return "cfb"
	case ModeOFB:
		return "ofb"
	case ModeCTR:
		return "ctr"
	case ModeCTRACPKM:
		return "ctr-acpkm"
	case ModeMAC:
		return "mac"
	case ModeMGM:
		return "mgm"
	default:
		return "unknown"
	}
}

func ParseMode(s string) (Mode, error) {
	switch normalizeName(s) {
	case "ecb":
		return ModeECB, nil
	case "cbc":
		return ModeCBC, nil
	case "cfb":
		return ModeCFB, nil
	case "ofb":
		return ModeOFB, nil
	case "ctr":
		return ModeCTR, nil
	case "ctracpkm", "acpkm":
		return ModeCTRACPKM, nil
	case "mac", "imit", "imitovstavka":
		return ModeMAC, nil
	case "mgm", "aead":
		return ModeMGM, nil
	default:
		return ModeUnknown, ErrInvalidMode
	}
}

func normalizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "_", "")
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, ".", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}
