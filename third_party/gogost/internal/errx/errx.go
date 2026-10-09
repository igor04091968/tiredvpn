// Package errx содержит лёгкие вспомогательные функции для сборки ошибок без тяжёлого форматирования.
package errx

import "strconv"

type wrapped struct {
	err error
	msg string
}

func (e wrapped) Error() string {
	if e.msg == "" {
		return e.err.Error()
	}
	return e.err.Error() + ": " + e.msg
}

func (e wrapped) Unwrap() error { return e.err }

// Wrap добавляет сообщение к err и сохраняет err для errors.Is/errors.As.
func Wrap(err error, msg string) error {
	if err == nil {
		return nil
	}
	return wrapped{err: err, msg: msg}
}

// PrefixText добавляет текстовый префикс к причине err.
func PrefixText(prefix string, err error) error {
	if err == nil {
		return nil
	}
	return prefixed{prefix: prefix, err: err}
}

type prefixed struct {
	prefix string
	err    error
}

func (e prefixed) Error() string {
	if e.prefix == "" {
		return e.err.Error()
	}
	return e.prefix + ": " + e.err.Error()
}

func (e prefixed) Unwrap() error { return e.err }

// Int возвращает десятичную запись n без fmt.
func Int(n int) string { return strconv.Itoa(n) }

// Uint8 возвращает десятичную запись n без fmt.
func Uint8(n uint8) string { return strconv.Itoa(int(n)) }

// GotWant форматирует диагностическое сообщение "получено/ожидалось".
func GotWant(got, want int) string {
	return "получено " + Int(got) + ", ожидалось " + Int(want)
}

// GotWantOr форматирует диагностическое сообщение с двумя допустимыми значениями.
func GotWantOr(got, wantA, wantB int) string {
	return "получено " + Int(got) + ", ожидалось " + Int(wantA) + " или " + Int(wantB)
}

// GotWantRange форматирует диагностическое сообщение с диапазоном допустимых значений.
func GotWantRange(got, min, max int) string {
	return "получено " + Int(got) + ", ожидалось " + Int(min) + ".." + Int(max)
}

// PanicText преобразует recovered panic в короткий текст без fmt.
func PanicText(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case error:
		return x.Error()
	case interface{ String() string }:
		return x.String()
	default:
		return "panic"
	}
}
