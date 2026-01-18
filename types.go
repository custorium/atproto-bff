package main

type VerifierClientMetadata struct {
	ClientID string `json:"client_id"`

	// All scope values which might be requested by the client are declared here. The `atproto` scope is required, so must be included here.
	Scope string `json:"scope"`

	// `vp_token` must be included
	ResponseTypes []string `json:"response_types"`

	// At least one redirect URI is required.
	RedirectURIs []string `json:"redirect_uris"`
}
