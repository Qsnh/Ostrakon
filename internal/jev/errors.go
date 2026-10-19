package jev

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"ostrakon/internal/apikey"
)

// APIError is a non-2xx response from Jev.
type APIError struct {
	Status     int
	Body       string        // at most maxErrorBody bytes of the response body
	RetryAfter time.Duration // from an integer-seconds Retry-After header, else 0
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("jev: HTTP %d", e.Status)
	// Keep the message to one short line: bodies can be large and multi-line.
	body := strings.Join(strings.Fields(e.Body), " ")
	if body == "" {
		return msg
	}
	const maxShown = 200
	if len(body) > maxShown {
		body = strings.ToValidUTF8(body[:maxShown], "") + "..."
	}
	return msg + ": " + body
}

// transportError marks a failure to complete the HTTP exchange (dial, TLS,
// timeout, connection dropped mid-body) while the caller's context was still
// alive. net/http reports its own Client.Timeout as an error that matches
// context.DeadlineExceeded, so Classify needs this marker to tell it apart
// from the caller giving up.
type transportError struct{ err error }

func (e *transportError) Error() string { return "jev: request failed: " + e.err.Error() }
func (e *transportError) Unwrap() error { return e.err }

// Class says how a caller should react to a failed Jev call.
type Class int

const (
	// ClassRetryable: Jev or the network is unavailable; back off and retry.
	ClassRetryable Class = iota
	// ClassAuth: the key is missing or rejected, or the account or endpoint
	// is unusable (billing, forbidden, wrong URL); retrying cannot help, so
	// the caller should pause immediately.
	ClassAuth
	// ClassBadRequest: this one request is unusable (400, 413, 415, 422 or an
	// unusable answer); drop this decision without treating Jev as unavailable.
	ClassBadRequest
	// ClassCanceled: the caller's context ended; not a Jev failure.
	ClassCanceled
)

// Classify maps an error from SystemOne (or from code that wraps it) to a Class.
//
// For an *APIError, only the request-error statuses 400, 413, 415 and 422 are
// ClassBadRequest, because only they say the problem is this one request.
// 401, 402, 403, 404, 405 and 410 are ClassAuth: the key, the account or the
// endpoint is unusable and no retry will fix it. Every other status (429, 529,
// 408, 425, any 5xx, any other 4xx, even an unexpected 3xx) is ClassRetryable,
// so a persistent failure ends in a visible pause instead of silently dropped
// decisions.
//
// For other errors: a missing key is ClassAuth, a done caller context is
// ClassCanceled, transport failures are ClassRetryable, and anything
// unrecognized, including a nil error, is ClassBadRequest.
func Classify(err error) Class {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		switch apiErr.Status {
		case 400, 413, 415, 422:
			return ClassBadRequest
		case 401, 402, 403, 404, 405, 410:
			return ClassAuth
		default:
			return ClassRetryable
		}
	}
	if errors.Is(err, apikey.ErrNoKey) {
		return ClassAuth
	}
	var te *transportError
	if errors.As(err, &te) {
		return ClassRetryable
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ClassCanceled
	}
	var ne net.Error
	var ue *url.Error
	if errors.As(err, &ne) || errors.As(err, &ue) {
		return ClassRetryable
	}
	return ClassBadRequest
}
