package witwpt

import (
	"errors"
	"fmt"
)

// errReplayed is the cause reported when a proof's jti has already been
// recorded. It is unexported deliberately: callers distinguish failures by
// Stage, which is stable, rather than by matching sentinel values.
var errReplayed = errors.New("proof token has already been used")

// Stage identifies which step of verification rejected a request. It is
// machine-readable so a rejection can be counted, not only logged.
type Stage int

const (
	// StageWIT covers validating the WIT-SVID against the trust bundle: its
	// typ, kid, signature, expiry, subject, and confirmation key. An unfederated
	// trust domain and an unknown key ID both land here, because witsvid
	// reports them through one call whose wrapped error carries the detail.
	StageWIT Stage = iota + 1

	// StageProof covers verifying the WPT against the confirmation key the
	// WIT-SVID named, including its binding to that credential and to the target.
	StageProof

	// StageReplay covers a proof whose jti has already been recorded.
	StageReplay
)

// String returns a short, stable label suitable for use as a metric dimension.
func (s Stage) String() string {
	switch s {
	case StageWIT:
		return "wit"
	case StageProof:
		return "proof"
	case StageReplay:
		return "replay"
	default:
		return "unknown"
	}
}

// Error is a verification failure together with the stage that produced it.
//
// Verify returns errors of this type so an operator's error handler can count
// rejections by stage while the caller is told only that it was refused. This is
// a deliberate exception to the surrounding convention of opaque wrapped errors:
// Verify is the one place where the caller-facing message is intentionally
// uninformative, so it is the one place a typed error earns its keep.
type Error struct {
	// Stage is the step that rejected the request.
	Stage Stage

	// Err is the underlying cause.
	Err error
}

func (e *Error) Error() string {
	var what string
	switch e.Stage {
	case StageWIT:
		what = "WIT-SVID validation failed"
	case StageProof:
		what = "proof verification failed"
	case StageReplay:
		what = "replay check failed"
	default:
		what = "verification failed"
	}
	return fmt.Sprintf("witwpt: %s: %v", what, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// newError builds a staged verification error.
func newError(stage Stage, err error) error {
	return &Error{Stage: stage, Err: err}
}
