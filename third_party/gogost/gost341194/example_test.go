package gost341194_test

import (
	"fmt"

	"gitverse.ru/uzer_007/gogost/v3/gost341194"
)

func Example() {
	h := gost341194.New(gost341194.SboxDefault)
	_, _ = h.Write([]byte("gogost"))
	sum := h.Sum(nil)

	fmt.Println(len(sum))
	// Output: 32
}
