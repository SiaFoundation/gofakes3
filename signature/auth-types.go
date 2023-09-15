package signature

import (
	"net/http"
	"net/url"
	"strings"
)

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

// Verify if request has AWS Signature Version '4'.
func isRequestSignatureV4(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get(headerAuth), "AWS4-HMAC-SHA256")
}

// Verify if the request has AWS Streaming Signature Version '4'. This is only valid for 'PUT' operation.
func isRequestSignStreamingV4(r *http.Request) bool {
	return r.Header.Get("X-Amz-Content-Sha256") == streamingContentSHA256 &&
		r.Method == http.MethodPut
}

// Verify if the request has AWS Streaming Signature Version '4'. This is only valid for 'PUT' operation.
func isRequestSignStreamingTrailerV4(r *http.Request) bool {
	return r.Header.Get("X-Amz-Content-Sha256") == streamingContentSHA256Trailer &&
		r.Method == http.MethodPut
}

// Verify if the request has AWS Streaming Signature Version '4', with unsigned content and trailer.
func isRequestUnsignedTrailerV4(r *http.Request) bool {
	return r.Header.Get("X-Amz-Content-Sha256") == "STREAMING-UNSIGNED-PAYLOAD-TRAILER" &&
		r.Method == http.MethodPut && strings.Contains(r.Header.Get("Content-Encoding"), "aws-chunked")
}

// Get request authentication type.
func getRequestAuthType(r *http.Request) (at authType) {
	if r.URL != nil {
		var err error
		r.Form, err = url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			return authTypeUnknown
		}
	}
	if isRequestSignStreamingV4(r) {
		return authTypeStreamingSigned
	} else if isRequestSignStreamingTrailerV4(r) {
		return authTypeStreamingSignedTrailer
	} else if isRequestUnsignedTrailerV4(r) {
		return authTypeStreamingUnsignedTrailer
	} else if isRequestSignatureV4(r) {
		return authTypeSigned
	}
	return authTypeUnknown
}

func IsSupportedAuthentication(req *http.Request) bool {
	return getRequestAuthType(req) != authTypeUnknown
}
