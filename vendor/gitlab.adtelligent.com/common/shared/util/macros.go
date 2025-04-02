package util

func MacrosIsNotReplaced(macros []byte) bool {
	return 0 == len(macros) ||
		macros[0] == '[' ||
		macros[0] == '%' ||
		macros[0] == '$' ||
		macros[0] == '{' ||
		UnsafeBytes2Str(macros) == "undefined"
}
