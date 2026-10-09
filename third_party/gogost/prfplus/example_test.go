package prfplus_test

import (
	"fmt"

	"gitverse.ru/uzer_007/gogost/v3/prfplus"
)

func Example() {
	prf := prfplus.NewPRFIPsecPRFPlusGOSTR34112012256([]byte("shared secret"))
	out := make([]byte, 48)
	prfplus.PRFPlus(prf, out, []byte("salt"))

	fmt.Println(len(out))
	// Output: 48
}
