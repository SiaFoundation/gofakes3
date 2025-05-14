package signature

// ref: https://github.com/minio/minio/master/cmd/auth-handler.go

type authType int

// List of all supported auth types.
const (
	authTypeUnknown authType = iota
	authTypeStreamingSigned
	authTypeSigned
	authTypeStreamingSignedTrailer
	authTypeStreamingUnsignedTrailer
)
