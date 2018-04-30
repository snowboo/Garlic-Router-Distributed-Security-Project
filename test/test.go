package main

import (
	"encoding/json"
	"fmt"
)

type s struct {
	Int       int
	String    string
	ByteSlice []byte
}

func main() {

	a := &s{42, "Hello World!", []byte{0, 1, 2, 3, 4}}

	// out_val, err := json.Marshal(a)
	// value := string(out_val)

	value := convertStructToString(a)

	fmt.Println("The data value: " + value)

	byte_v := convertStringToByte(value)
	fmt.Println("The byte array: ", byte_v)

	message := []byte("message to be signed")
	fmt.Println("The byte array: " + string(message[:]))
}

func convertStructToString(val interface{}) string {
	ret_val, _ := json.Marshal(val)
	return string(ret_val)
}

func convertStringToByte(val string) []byte {
	return []byte(val)
}
