package httprouter

import (
	"context"
	"fmt"
	"go/token"
	"net/http"
	"strings"
)

// HandlePattern registers a handler using a Go 1.22-style routing pattern.
//
// Supported pattern forms:
//   - "METHOD /path"
//   - "/path" (matches any HTTP method)
//
// Supported path wildcards:
//   - {name}      -> single path segment
//   - {name...}   -> remaining path (must be final segment)
//   - {$}         -> end anchor for trailing slash exactness
//
// Host-based patterns (e.g. "example.com/path") are currently unsupported.
func (r *Router) HandlePattern(pattern string, handle Handle) {
	method, path, err := parsePattern(pattern)
	if err != nil {
		panic(err.Error())
	}

	translatedPath, err := translatePatternPath(path)
	if err != nil {
		panic(err.Error())
	}

	if method == "" {
		r.handle(anyMethod, translatedPath, handle, true)
		return
	}

	if method == http.MethodGet {
		r.HandleHEADWithGET = true
	}

	r.Handle(method, translatedPath, handle)
}

// HandlerPattern is the pattern-based equivalent of Router.Handler.
func (r *Router) HandlerPattern(pattern string, handler http.Handler) {
	r.HandlePattern(pattern,
		func(w http.ResponseWriter, req *http.Request, p Params) {
			if len(p) > 0 {
				ctx := req.Context()
				ctx = context.WithValue(ctx, ParamsKey, p)
				req = req.WithContext(ctx)
			}
			handler.ServeHTTP(w, req)
		},
	)
}

// HandlerFuncPattern is the pattern-based equivalent of Router.HandlerFunc.
func (r *Router) HandlerFuncPattern(pattern string, handler http.HandlerFunc) {
	r.HandlerPattern(pattern, handler)
}

func parsePattern(pattern string) (method, path string, err error) {
	parts := strings.Fields(pattern)
	switch len(parts) {
	case 0:
		return "", "", fmt.Errorf("invalid pattern %q: pattern must not be empty", pattern)
	case 1:
		path = parts[0]
	case 2:
		method = parts[0]
		path = parts[1]
	default:
		return "", "", fmt.Errorf("invalid pattern %q: expected [METHOD] /path", pattern)
	}

	if len(path) == 0 || path[0] != '/' {
		return "", "", fmt.Errorf("invalid pattern %q: path must start with '/' (host patterns are not supported)", pattern)
	}

	return method, path, nil
}

func translatePatternPath(path string) (string, error) {
	segments := strings.Split(path, "/")
	translated := make([]string, 0, len(segments)-1)

	for i := 1; i < len(segments); i++ {
		segment := segments[i]
		last := i == len(segments)-1

		switch {
		case segment == "{$}":
			if !last {
				return "", fmt.Errorf("invalid path pattern %q: {$} is only allowed at the end", path)
			}
			translated = append(translated, "")

		case segment == "":
			translated = append(translated, "")

		case strings.ContainsAny(segment, "{}"):
			wildcard, err := translateWildcardSegment(path, segment, last)
			if err != nil {
				return "", err
			}
			translated = append(translated, wildcard)

		default:
			translated = append(translated, segment)
		}
	}

	return "/" + strings.Join(translated, "/"), nil
}

func translateWildcardSegment(path, segment string, last bool) (string, error) {
	if len(segment) < 2 || segment[0] != '{' || segment[len(segment)-1] != '}' {
		return "", fmt.Errorf("invalid path pattern %q: malformed wildcard segment %q", path, segment)
	}

	name := segment[1 : len(segment)-1]
	if name == "" {
		return "", fmt.Errorf("invalid path pattern %q: wildcard %q has an empty name", path, segment)
	}

	if strings.HasSuffix(name, "...") {
		name = strings.TrimSuffix(name, "...")
		if name == "" || !token.IsIdentifier(name) {
			return "", fmt.Errorf("invalid path pattern %q: wildcard name %q is not a valid identifier", path, name)
		}
		if !last {
			return "", fmt.Errorf("invalid path pattern %q: catch-all wildcard %q must be the final segment", path, segment)
		}
		return "*" + name, nil
	}

	if strings.Contains(name, "...") {
		return "", fmt.Errorf("invalid path pattern %q: wildcard %q is malformed", path, segment)
	}
	if !token.IsIdentifier(name) {
		return "", fmt.Errorf("invalid path pattern %q: wildcard name %q is not a valid identifier", path, name)
	}

	return ":" + name, nil
}
