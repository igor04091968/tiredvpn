// Package gost3413 реализует способы дополнения блоков из ГОСТ Р 34.13-2015.
package gost3413

// PadSize возвращает размер заполнения для данных, чтобы они соответствовали размеру блока.
// dataSize - размер данных.
// blockSize - размер блока.
func PadSize(dataSize, blockSize int) int {
	// Если размер данных меньше размера блока, возвращаем разницу между размером блока и размером данных.
	if dataSize < blockSize {
		return blockSize - dataSize
	}
	// Если размер данных кратен размеру блока, возвращаем 0.
	if dataSize%blockSize == 0 {
		return 0
	}
	// В противном случае возвращаем разницу между размером блока и остатком от деления размера данных на размер блока.
	return blockSize - dataSize%blockSize
}

func Pad1(data []byte, blockSize int) []byte {
	padSize := PadSize(len(data), blockSize)
	if padSize == 0 {
		return data
	}
	return append(data, make([]byte, padSize)...)
}

func Pad2(data []byte, blockSize int) []byte {
	pad := make([]byte, 1+PadSize(len(data)+1, blockSize))
	pad[0] = byte(0x80)
	return append(data, pad...)
}

func Pad3(data []byte, blockSize int) []byte {
	if PadSize(len(data), blockSize) == 0 {
		return data
	}
	return Pad2(data, blockSize)
}
