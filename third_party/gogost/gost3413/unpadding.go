package gost3413

import (
	"errors"
)

// Unpad1 удаляет паддинг, добавленный методом Pad1
func Unpad1(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("gogost/gost3413: Ошибка размера данных для padding")
	}

	// Найти последний ненулевой байт
	i := len(data)
	for i > 0 && data[i-1] == 0 {
		i--
	}

	return data[:i], nil
}

// Unpad2 удаляет паддинг, добавленный методом Pad2
func Unpad2(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("gogost/gost3413: Ошибка размера данных для padding")
	}

	// Найти байт 0x80
	i := len(data) - 1
	for i >= 0 && data[i] == 0 {
		i--
	}
	if i < 0 || data[i] != 0x80 {
		return nil, errors.New("gogost/gost3413: Ошибка при удалении padding")
	}

	return data[:i], nil
}

func Unpad3(data []byte, blockSize int) ([]byte, error) {
	return Unpad2(data, blockSize)
}
