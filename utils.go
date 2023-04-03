package auth

// sliceIndex returns the index of the first occurrence of v in s,
// or -1 if not present.
func sliceIndex[E comparable](s []E, v E) int {
	for i, vs := range s {
		if v == vs {
			return i
		}
	}
	return -1
}

// sliceContains reports whether v is present in s.
func sliceContains[E comparable](s []E, v E) bool {
	return sliceIndex(s, v) >= 0
}
