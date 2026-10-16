// Package auth is the bearer-token middleware and the Principal type:
// constant-time comparison of a single configured token, a 401 with
// WWW-Authenticate: Bearer realm="shell-mcp" and {"error":"unauthorized"},
// and the auth-failure limiter (10 presented-but-wrong credentials per 5
// minutes per client → 429 for 5 minutes; a request with no Authorization
// header gets the 401 but does not count). It never logs or returns a token
// or the Authorization header.
package auth
