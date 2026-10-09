package gost3413_test

import (
	"fmt"

	"gitverse.ru/uzer_007/gogost/v3/gost3413"
)

func Example() {
	padded := gost3413.Pad2([]byte("data"), 8)
	plain, err := gost3413.Unpad2(padded, 8)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(plain), len(padded))
	// Output: data 8
}
