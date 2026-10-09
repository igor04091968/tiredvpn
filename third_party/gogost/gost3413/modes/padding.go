package modes

import "gitverse.ru/uzer_007/gogost/v3/internal/errx"

func validatePadding(p Padding) error {
	switch p {
	case PaddingNone, Padding1, Padding2, Padding3:
		return nil
	default:
		return errx.Wrap(ErrInvalidPadding, errx.Int(int(p)))
	}
}

func padSize(dataSize, blockSize int) int {
	if dataSize < blockSize {
		return blockSize - dataSize
	}
	if dataSize%blockSize == 0 {
		return 0
	}
	return blockSize - dataSize%blockSize
}

func paddedSize(dataSize, blockSize int, p Padding) (int, error) {
	switch p {
	case PaddingNone:
		if dataSize%blockSize != 0 {
			return 0, errx.Wrap(ErrInvalidInput, "длина plaintext "+errx.Int(dataSize)+" не кратна размеру блока")
		}
		return dataSize, nil
	case Padding1:
		return dataSize + padSize(dataSize, blockSize), nil
	case Padding2:
		return dataSize + 1 + padSize(dataSize+1, blockSize), nil
	case Padding3:
		if padSize(dataSize, blockSize) == 0 {
			return dataSize, nil
		}
		return dataSize + 1 + padSize(dataSize+1, blockSize), nil
	default:
		return 0, errx.Wrap(ErrInvalidPadding, errx.Int(int(p)))
	}
}

func padInto(out, data []byte, blockSize int, p Padding) error {
	switch p {
	case PaddingNone:
		copy(out, data)
	case Padding1:
		copy(out, data)
		clear(out[len(data):])
	case Padding2:
		copy(out, data)
		clear(out[len(data):])
		out[len(data)] = 0x80
	case Padding3:
		copy(out, data)
		if len(out) != len(data) {
			clear(out[len(data):])
			out[len(data)] = 0x80
		}
	default:
		return errx.Wrap(ErrInvalidPadding, errx.Int(int(p)))
	}
	if len(out)%blockSize != 0 {
		return errx.Wrap(ErrInvalidInput, "длина данных с padding "+errx.Int(len(out)))
	}
	return nil
}

func unpad(data []byte, blockSize int, p Padding) ([]byte, error) {
	if len(data)%blockSize != 0 {
		return nil, errx.Wrap(ErrInvalidInput, "длина plaintext "+errx.Int(len(data))+" не кратна размеру блока")
	}
	switch p {
	case PaddingNone:
		return data, nil
	case Padding1:
		i := len(data)
		for i > 0 && data[i-1] == 0 {
			i--
		}
		return data[:i], nil
	case Padding2:
		return unpad2(data)
	case Padding3:
		plain, err := unpad2(data)
		if err == nil {
			return plain, nil
		}
		return data, nil
	default:
		return nil, errx.Wrap(ErrInvalidPadding, errx.Int(int(p)))
	}
}

func unpad2(data []byte) ([]byte, error) {
	i := len(data) - 1
	for i >= 0 && data[i] == 0 {
		i--
	}
	if i < 0 || data[i] != 0x80 {
		return nil, errx.Wrap(ErrInvalidInput, "некорректный padding")
	}
	return data[:i], nil
}
