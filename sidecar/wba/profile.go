package wba

// Profile pins one revision of the Web Bot Auth drafts.
//
// The drafts are individual Internet-Drafts, not working-group adopted, and
// they move — the directory draft has already been renamed once. Encoding their
// rules as data in one place means a new revision is a new profile rather than
// a scattering of edits, and every verdict records which profile judged it.
type Profile struct {
	ID                 string
	Tracks             string
	Tag                string
	DirectoryPath      string
	DirectoryMediaType string
	Algorithms         []string
	// RequiredComponents holds groups of alternatives: a group is satisfied by
	// covering any one of its members. @target-uri is a legitimate and strictly
	// stronger substitute for @authority, since it contains the authority and
	// additionally pins scheme, path and query.
	RequiredComponents            [][]string
	RequiredComponentsWhenPresent []string
	RequireSignatureAgent         bool
	RequireKeyid                  bool
	RequireCreated                bool
	RequireExpires                bool
	MaxWindowSec                  int64
}

// WBA202603 tracks the drafts as of March 2026.
var WBA202603 = Profile{
	ID: "wba-2026-03",
	Tracks: "draft-meunier-web-bot-auth-architecture-05, " +
		"draft-meunier-webbotauth-httpsig-protocol-02, " +
		"draft-meunier-webbotauth-httpsig-directory-00",
	Tag:                           "web-bot-auth",
	DirectoryPath:                 "/.well-known/http-message-signatures-directory",
	DirectoryMediaType:            "application/http-message-signatures-directory+json",
	Algorithms:                    []string{"ed25519"},
	RequiredComponents:            [][]string{{"@authority", "@target-uri"}},
	RequiredComponentsWhenPresent: []string{"signature-agent"},
	RequireSignatureAgent:         true,
	RequireKeyid:                  true,
	RequireCreated:                true,
	RequireExpires:                true,
	MaxWindowSec:                  86400,
}

// DefaultProfile is used when a caller does not choose one.
var DefaultProfile = WBA202603
