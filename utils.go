package merkle

// Returns true if n is a power of 2
func isPowerOfTwo(n uint64) bool {
	// http://graphics.stanford.edu/~seander/bithacks.html#DetermineIfPowerOf2
	return n != 0 && (n&(n-1)) == 0
}

// Returns the next highest power of 2 above n, if n is not already a
// power of 2
func nextPowerOfTwo(n uint64) uint64 {
	if n == 0 {
		return 1
	}
	// http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	n |= n >> 32
	n++
	return n
}

// Lookup table for integer log2 implementation
var log2lookup []uint64 = []uint64{
	0xFFFFFFFF00000000,
	0x00000000FFFF0000,
	0x000000000000FF00,
	0x00000000000000F0,
	0x000000000000000C,
	0x0000000000000002,
}

// Returns log2(n) assuming n is a power of 2
func logBaseTwo(x uint64) uint64 {
	if x == 0 {
		return 0
	}
	ct := uint64(0)
	for x != 0 {
		x >>= 1
		ct += 1
	}
	return ct - 1
}

// Returns the ceil'd log2 value of n
// See: http://stackoverflow.com/a/15327567
func ceilLogBaseTwo(x uint64) uint64 {
	y := uint64(1)
	if (x & (x - 1)) == 0 {
		y = 0
	}
	j := uint64(32)
	i := uint64(0)

	for ; i < 6; i++ {
		k := j
		if (x & log2lookup[i]) == 0 {
			k = 0
		}
		y += k
		x >>= k
		j >>= 1
	}

	return y
}
