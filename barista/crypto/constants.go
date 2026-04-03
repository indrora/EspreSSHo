package crypto

// EC Point constants
const (
	// ECPointLength is the length of an uncompressed P-256 EC point (1 + 32 + 32 bytes)
	ECPointLength = 65
	
	// ECUncompressedPrefix is the prefix byte for uncompressed EC points
	ECUncompressedPrefix = 0x04
)

// APDU Status Word constants
const (
	// APDUSuccess indicates successful APDU execution
	APDUSuccess = 0x9000
)

// Timeout constants
const (
	// MaxTimeoutMinutes is the maximum timeout value for PIN validation
	MaxTimeoutMinutes = 7
)