package httprouter

import (
	"context"
	"fmt"
	"go/token"
	"net/http"
	"net/url"
	"strings"
)

type parsedPattern struct {
	method     string
	host       string
	path       string
	paramNames []string
	tokens     []patternPathToken
}

type patternPathTokenKind uint8

const (
	patternLiteral patternPathTokenKind = iota
	patternParam
	patternCatchAll
	patternEndAnchor
)

type patternPathToken struct {
	kind  patternPathTokenKind
	value string
}

// HandlePattern registers a handler using a Go 1.22 ServeMux-style pattern.
//
// Pattern matching, precedence, host routing, and method handling semantics are
// delegated to net/http.ServeMux for compatibility.
func (r *Router) HandlePattern(pattern string, handle Handle) {
	if handle == nil {
		panic("handle must not be nil")
	}

	parsed, err := parseServeMuxPattern(pattern)
	if err != nil {
		panic(err.Error())
	}

	if r.patternMux == nil {
		r.patternMux = http.NewServeMux()
	}
	if parsed.method != "" {
		if r.patternMethods == nil {
			r.patternMethods = make(map[string]struct{})
		}
		r.patternMethods[parsed.method] = struct{}{}
	}

	varsCount := uint16(len(parsed.paramNames))
	if r.SaveMatchedRoutePath {
		varsCount++
	}
	if varsCount > r.maxParams {
		r.maxParams = varsCount
	}
	if r.paramsPool.New == nil && r.maxParams > 0 {
		r.paramsPool.New = func() interface{} {
			ps := make(Params, 0, r.maxParams)
			return &ps
		}
	}

	paramNames := append([]string(nil), parsed.paramNames...)
	tokens := append([]patternPathToken(nil), parsed.tokens...)
	matchedRoutePath := parsed.path
	matchedPattern := pattern

	r.patternMux.Handle(pattern, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		n := len(paramNames)
		if r.SaveMatchedRoutePath {
			n++
		}
		if n == 0 {
			req.Pattern = matchedPattern
			handle(w, req, nil)
			return
		}

		psp := r.getParams()
		*psp = (*psp)[:n]

		if len(paramNames) > 0 {
			if !fillPatternParamsFromRequest(req, tokens, *psp) {
				for i, name := range paramNames {
					v := req.PathValue(name)
					(*psp)[i] = Param{Key: name, Value: v}
					req.SetPathValue(name, v)
				}
			}
		}
		if r.SaveMatchedRoutePath {
			(*psp)[len(paramNames)] = Param{Key: MatchedRoutePathParam, Value: matchedRoutePath}
		}

		req.Pattern = matchedPattern
		handle(w, req, *psp)
		r.putParams(psp)
	}))
}

func fillPatternParamsFromRequest(req *http.Request, tokens []patternPathToken, out Params) bool {
	path := req.URL.Path
	if len(path) == 0 || path[0] != '/' {
		return false
	}

	paramIndex := 0
	pos := 1 // skip leading slash

	for i, token := range tokens {
		switch token.kind {
		case patternEndAnchor:
			if i != len(tokens)-1 {
				return false
			}
			return pos == len(path)

		case patternCatchAll:
			if i != len(tokens)-1 {
				return false
			}
			value := unescapePatternCatchAll(path[pos:])
			out[paramIndex] = Param{Key: token.value, Value: value}
			req.SetPathValue(token.value, value)
			paramIndex++
			return true

		default:
			start := pos
			for pos < len(path) && path[pos] != '/' {
				pos++
			}
			segment := path[start:pos]

			if token.kind == patternLiteral {
				if segment != token.value {
					return false
				}
			} else {
				value := unescapePatternSegment(segment)
				out[paramIndex] = Param{Key: token.value, Value: value}
				req.SetPathValue(token.value, value)
				paramIndex++
			}

			if pos < len(path) {
				pos++ // skip '/'
			}
		}
	}

	return pos == len(path)
}

func unescapePatternSegment(segment string) string {
	if strings.IndexByte(segment, '%') < 0 {
		return segment
	}
	if unescaped, err := url.PathUnescape(segment); err == nil {
		return unescaped
	}
	return segment
}

func unescapePatternCatchAll(value string) string {
	if strings.IndexByte(value, '%') < 0 {
		return value
	}

	parts := strings.Split(value, "/")
	for i, part := range parts {
		parts[i] = unescapePatternSegment(part)
	}
	return strings.Join(parts, "/")
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

func parseServeMuxPattern(pattern string) (parsedPattern, error) {
	parts := strings.Fields(pattern)
	if len(parts) == 0 {
		return parsedPattern{}, fmt.Errorf("invalid pattern %q: pattern must not be empty", pattern)
	}
	if len(parts) > 2 {
		return parsedPattern{}, fmt.Errorf("invalid pattern %q: expected [METHOD] [HOST]/path", pattern)
	}

	var method, target string
	if len(parts) == 1 {
		target = parts[0]
	} else {
		method = parts[0]
		target = parts[1]
	}

	slash := strings.IndexByte(target, '/')
	if slash < 0 {
		return parsedPattern{}, fmt.Errorf("invalid pattern %q: expected [HOST]/path", pattern)
	}

	host := ""
	path := target
	if slash > 0 {
		host = target[:slash]
		path = target[slash:]
	}
	if len(path) == 0 || path[0] != '/' {
		return parsedPattern{}, fmt.Errorf("invalid pattern %q: path must start with '/'", pattern)
	}

	tokens, paramNames, err := compilePatternPath(path)
	if err != nil {
		return parsedPattern{}, fmt.Errorf("invalid pattern %q: %w", pattern, err)
	}

	return parsedPattern{
		method:     method,
		host:       host,
		path:       path,
		paramNames: paramNames,
		tokens:     tokens,
	}, nil
}

func compilePatternPath(path string) ([]patternPathToken, []string, error) {
	segments := strings.Split(path, "/")[1:]
	tokens := make([]patternPathToken, 0, len(segments))
	paramNames := make([]string, 0, 4)

	for i, segment := range segments {
		last := i == len(segments)-1

		switch {
		case segment == "{$}":
			if !last {
				return nil, nil, fmt.Errorf("{$} is only allowed at the end of the path")
			}
			tokens = append(tokens, patternPathToken{kind: patternEndAnchor})

		case strings.ContainsAny(segment, "{}"):
			if len(segment) < 2 || segment[0] != '{' || segment[len(segment)-1] != '}' {
				return nil, nil, fmt.Errorf("malformed wildcard segment %q", segment)
			}
			inner := segment[1 : len(segment)-1]
			if inner == "" {
				return nil, nil, fmt.Errorf("wildcard %q has an empty name", segment)
			}
			if inner == "$" {
				if !last {
					return nil, nil, fmt.Errorf("{$} is only allowed at the end of the path")
				}
				tokens = append(tokens, patternPathToken{kind: patternEndAnchor})
				continue
			}

			if strings.HasSuffix(inner, "...") {
				name := strings.TrimSuffix(inner, "...")
				if !last {
					return nil, nil, fmt.Errorf("catch-all wildcard %q must be the final path segment", segment)
				}
				if name == "" || !token.IsIdentifier(name) {
					return nil, nil, fmt.Errorf("wildcard name %q is not a valid identifier", name)
				}
				tokens = append(tokens, patternPathToken{kind: patternCatchAll, value: name})
				paramNames = append(paramNames, name)
				continue
			}

			if strings.Contains(inner, "...") {
				return nil, nil, fmt.Errorf("wildcard %q is malformed", segment)
			}
			if !token.IsIdentifier(inner) {
				return nil, nil, fmt.Errorf("wildcard name %q is not a valid identifier", inner)
			}
			tokens = append(tokens, patternPathToken{kind: patternParam, value: inner})
			paramNames = append(paramNames, inner)

		default:
			tokens = append(tokens, patternPathToken{kind: patternLiteral, value: segment})
		}
	}

	return tokens, paramNames, nil
}
