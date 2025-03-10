package util

import "math"

func pair(k1, k2 int) int {
	// http://en.wikipedia.org/wiki/Pairing_function#Cantor_pairing_function
	return int(0.5*(float64(k1)+float64(k2))*(float64(k1)+float64(k2)+1) + float64(k2))
}

func depair(p int) (int, int) {
	// http://en.wikipedia.org/wiki/Pairing_function#Inverting_the_Cantor_pairing_function
	w := math.Floor((math.Sqrt(8*float64(p)+1) - 1) / 2)

	t := (math.Pow(w, 2) + w) / 2

	y := float64(p) - t
	x := w - y

	return int(x), int(y)
}
