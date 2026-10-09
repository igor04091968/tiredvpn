package gost3412128

type streamBackend struct {
	name string
}

var activeStreamBackend = selectStreamBackend()
