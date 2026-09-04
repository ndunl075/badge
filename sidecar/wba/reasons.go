// Package wba implements Web Bot Auth verification: verdicts, signature base
// construction and signature checking.
package wba

// Status is the headline verdict. It is never enough to act on by itself; see
// Class.
type Status string

const (
	StatusVerified Status = "verified"
	StatusClaimed  Status = "claimed"
	StatusUnknown  Status = "unknown"
)

// Class says what kind of outcome this was, and crucially whose fault it was.
//
// ClassUntrusted means the caller failed a check it controls: assume hostile.
// ClassUnverifiable means Badge could not complete the check — a directory
// timeout, a broken store, an internal error. Denying on that wires a site's
// availability to its own egress, so policy must be able to tell the two apart.
type Class string

const (
	ClassOK           Class = "ok"
	ClassAbsent       Class = "absent"
	ClassMalformed    Class = "malformed"
	ClassExpired      Class = "expired"
	ClassUntrusted    Class = "untrusted"
	ClassUnverifiable Class = "unverifiable"
)

// Reason is a stable, public reason code. Codes are added, never repurposed:
// a log line written a year ago must still mean what it meant then.
type Reason string

const (
	ReasonOK                            Reason = "ok"
	ReasonNoSignatureFields             Reason = "no_signature_fields"
	ReasonNoWebBotAuthTag               Reason = "no_web_bot_auth_tag"
	ReasonSignatureInputMalformed       Reason = "signature_input_malformed"
	ReasonSignatureMalformed            Reason = "signature_malformed"
	ReasonSignatureAgentMalformed       Reason = "signature_agent_malformed"
	ReasonSignatureAgentMissing         Reason = "signature_agent_missing"
	ReasonCoveredComponentsInsufficient Reason = "covered_components_insufficient"
	ReasonUnsupportedAlgorithm          Reason = "unsupported_algorithm"
	ReasonMissingKeyid                  Reason = "missing_keyid"
	ReasonMissingCreated                Reason = "missing_created"
	ReasonMissingExpires                Reason = "missing_expires"
	ReasonValidityWindowTooLong         Reason = "validity_window_too_long"
	ReasonNonceMissing                  Reason = "nonce_missing"
	ReasonNonceInvalid                  Reason = "nonce_invalid"
	ReasonCoveredComponentMissing       Reason = "covered_component_missing"
	ReasonCoveredFieldNotStructured     Reason = "covered_field_not_structured"
	ReasonCoveredComponentMalformed     Reason = "covered_component_malformed"
	ReasonCreatedInFuture               Reason = "created_in_future"
	ReasonSignatureExpired              Reason = "signature_expired"
	ReasonSignatureTooOld               Reason = "signature_too_old"
	ReasonKeyNotFound                   Reason = "key_not_found"
	ReasonKeyNotYetValid                Reason = "key_not_yet_valid"
	ReasonKeyExpired                    Reason = "key_expired"
	ReasonSignatureInvalid              Reason = "signature_invalid"
	ReasonReplayDetected                Reason = "replay_detected"
	ReasonSignatureAgentNotAllowed      Reason = "signature_agent_not_allowed"
	ReasonDirectoryUnreachable          Reason = "directory_unreachable"
	ReasonDirectoryTimeout              Reason = "directory_timeout"
	ReasonDirectoryMalformed            Reason = "directory_malformed"
	ReasonDirectoryTooLarge             Reason = "directory_too_large"
	ReasonNonceStoreUnavailable         Reason = "nonce_store_unavailable"
	ReasonUnsupportedComponent          Reason = "unsupported_component"
	ReasonInternalError                 Reason = "internal_error"
)

type reasonInfo struct {
	Status Status
	Class  Class
}

// reasons must stay identical to packages/core/src/reasons.ts. The shared
// verdict vectors in spec-vectors/ check that it does.
var reasons = map[Reason]reasonInfo{
	ReasonOK:                            {StatusVerified, ClassOK},
	ReasonNoSignatureFields:             {StatusUnknown, ClassAbsent},
	ReasonNoWebBotAuthTag:               {StatusUnknown, ClassAbsent},
	ReasonSignatureInputMalformed:       {StatusClaimed, ClassMalformed},
	ReasonSignatureMalformed:            {StatusClaimed, ClassMalformed},
	ReasonSignatureAgentMalformed:       {StatusClaimed, ClassMalformed},
	ReasonSignatureAgentMissing:         {StatusClaimed, ClassMalformed},
	ReasonCoveredComponentsInsufficient: {StatusClaimed, ClassMalformed},
	ReasonUnsupportedAlgorithm:          {StatusClaimed, ClassMalformed},
	ReasonMissingKeyid:                  {StatusClaimed, ClassMalformed},
	ReasonMissingCreated:                {StatusClaimed, ClassMalformed},
	ReasonMissingExpires:                {StatusClaimed, ClassMalformed},
	ReasonValidityWindowTooLong:         {StatusClaimed, ClassMalformed},
	ReasonNonceMissing:                  {StatusClaimed, ClassMalformed},
	ReasonNonceInvalid:                  {StatusClaimed, ClassMalformed},
	ReasonCoveredComponentMissing:       {StatusClaimed, ClassMalformed},
	ReasonCoveredFieldNotStructured:     {StatusClaimed, ClassMalformed},
	ReasonCoveredComponentMalformed:     {StatusClaimed, ClassMalformed},
	ReasonCreatedInFuture:               {StatusClaimed, ClassExpired},
	ReasonSignatureExpired:              {StatusClaimed, ClassExpired},
	ReasonSignatureTooOld:               {StatusClaimed, ClassExpired},
	ReasonKeyNotFound:                   {StatusClaimed, ClassUntrusted},
	ReasonKeyNotYetValid:                {StatusClaimed, ClassUntrusted},
	ReasonKeyExpired:                    {StatusClaimed, ClassUntrusted},
	ReasonSignatureInvalid:              {StatusClaimed, ClassUntrusted},
	ReasonReplayDetected:                {StatusClaimed, ClassUntrusted},
	ReasonSignatureAgentNotAllowed:      {StatusClaimed, ClassUntrusted},
	ReasonDirectoryUnreachable:          {StatusClaimed, ClassUnverifiable},
	ReasonDirectoryTimeout:              {StatusClaimed, ClassUnverifiable},
	ReasonDirectoryMalformed:            {StatusClaimed, ClassUnverifiable},
	ReasonDirectoryTooLarge:             {StatusClaimed, ClassUnverifiable},
	ReasonNonceStoreUnavailable:         {StatusClaimed, ClassUnverifiable},
	ReasonUnsupportedComponent:          {StatusClaimed, ClassUnverifiable},
	ReasonInternalError:                 {StatusClaimed, ClassUnverifiable},
}

// Info returns the status and class a reason code implies. This mapping is
// fixed.
func (r Reason) Info() (Status, Class) {
	info, ok := reasons[r]
	if !ok {
		// An unknown code is treated as our failure rather than the caller's:
		// we cannot say the request was bad if we cannot say what happened.
		return StatusClaimed, ClassUnverifiable
	}
	return info.Status, info.Class
}

// IsOurFault reports whether the reason means Badge failed, not the caller.
func (r Reason) IsOurFault() bool {
	_, class := r.Info()
	return class == ClassUnverifiable
}

// AllReasons lists every reason code, for tests and documentation.
func AllReasons() []Reason {
	out := make([]Reason, 0, len(reasons))
	for reason := range reasons {
		out = append(out, reason)
	}
	return out
}
