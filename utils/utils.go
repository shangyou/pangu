package utils

import (
	"io"
)

func ReadAll(reader io.ReadCloser) string {
	var str string
	for {
		buf := make([]byte, 1024)
		n, err := reader.Read(buf)

		if err != nil && err != io.EOF {
			panic(err)
		}

		if n == 0 {
			break
		}
		str += string(buf)
	}

	return str
}

func Change(header interface{}) string {
	data, _ := header.(string)
	return data
}
