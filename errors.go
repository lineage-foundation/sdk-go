package sdkgo

// APIError is a parsed `application/problem+json` error body returned by the
// `/v1` API on non-2xx responses, mirroring fleet_api::error::ApiProblem and
// sdk-js's IApiProblemResponse.
type APIError struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
	Code   string `json:"code,omitempty"`
}

// Error implements the error interface. It returns Detail when set (the
// occurrence-specific explanation), falling back to Title (the problem-type
// summary).
func (e *APIError) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	return e.Title
}
