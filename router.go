// Copyright 2013 Julien Schmidt. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

// Package httprouter is a trie based high performance HTTP request router.
//
// A trivial example is:
//
//	package main
//
//	import (
//	    "fmt"
//	    "github.com/julienschmidt/httprouter"
//	    "net/http"
//	    "log"
//	)
//
//	func Index(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
//	    fmt.Fprint(w, "Welcome!\n")
//	}
//
//	func Hello(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
//	    fmt.Fprintf(w, "hello, %s!\n", ps.ByName("name"))
//	}
//
//	func main() {
//	    router := httprouter.New()
//	    router.GET("/", Index)
//	    router.GET("/hello/:name", Hello)
//
//	    log.Fatal(http.ListenAndServe(":8080", router))
//	}
//
// The router matches incoming requests by the request method and the path.
// If a handle is registered for this path and method, the router delegates the
// request to that function.
// For the methods GET, POST, PUT, PATCH, DELETE and OPTIONS shortcut functions exist to
// register handles, for all other methods router.Handle can be used.
//
// The registered path, against which the router matches incoming requests, can
// contain two types of parameters:
//
//	Syntax    Type
//	:name     named parameter
//	*name     catch-all parameter
//
// Named parameters are dynamic path segments. They match anything until the
// next '/' or the path end:
//
//	Path: /blog/:category/:post
//
//	Requests:
//	 /blog/go/request-routers            match: category="go", post="request-routers"
//	 /blog/go/request-routers/           no match, but the router would redirect
//	 /blog/go/                           no match
//	 /blog/go/request-routers/comments   no match
//
// Catch-all parameters match anything until the path end, including the
// directory index (the '/' before the catch-all). Since they match anything
// until the end, catch-all parameters must always be the final path element.
//
//	Path: /files/*filepath
//
//	Requests:
//	 /files/                             match: filepath="/"
//	 /files/LICENSE                      match: filepath="/LICENSE"
//	 /files/templates/article.html       match: filepath="/templates/article.html"
//	 /files                              no match, but the router would redirect
//
// The value of parameters is saved as a slice of the Param struct, consisting
// each of a key and a value. The slice is passed to the Handle func as a third
// parameter.
// There are two ways to retrieve the value of a parameter:
//
//	// by the name of the parameter
//	user := ps.ByName("user") // defined by :user or *user
//
//	// by the index of the parameter. This way you can also get the name (key)
//	thirdKey   := ps[2].Key   // the name of the 3rd parameter
//	thirdValue := ps[2].Value // the value of the 3rd parameter
package httprouter

import (
	"context"
	"net/http"
	"strings"
	"sync"
)

// Handle is a function that can be registered to a route to handle HTTP
// requests. Like http.HandlerFunc, but has a third parameter for the values of
// wildcards (path variables).
type Handle func(http.ResponseWriter, *http.Request, Params)

// Param is a single URL parameter, consisting of a key and a value.
type Param struct {
	Key   string
	Value string
}

// Params is a Param-slice, as returned by the router.
// The slice is ordered, the first URL parameter is also the first slice value.
// It is therefore safe to read values by the index.
type Params []Param

// ByName returns the value of the first Param which key matches the given name.
// If no matching Param is found, an empty string is returned.
func (ps Params) ByName(name string) string {
	for _, p := range ps {
		if p.Key == name {
			return p.Value
		}
	}
	return ""
}

type paramsKey struct{}

// ParamsKey is the request context key under which URL params are stored.
var ParamsKey = paramsKey{}

// ParamsFromContext pulls the URL parameters from a request context,
// or returns nil if none are present.
func ParamsFromContext(ctx context.Context) Params {
	p, _ := ctx.Value(ParamsKey).(Params)
	return p
}

// MatchedRoutePathParam is the Param name under which the path of the matched
// route is stored, if Router.SaveMatchedRoutePath is set.
var MatchedRoutePathParam = "$matchedRoutePath"

// MatchedRoutePath retrieves the path of the matched route.
// Router.SaveMatchedRoutePath must have been enabled when the respective
// handler was added, otherwise this function always returns an empty string.
func (ps Params) MatchedRoutePath() string {
	return ps.ByName(MatchedRoutePathParam)
}

// Router is a http.Handler which can be used to dispatch requests to different
// handler functions via configurable routes
type Router struct {
	trees map[string]*node

	getTree         *node
	headTree        *node
	postTree        *node
	putTree         *node
	patchTree       *node
	deleteTree      *node
	optionsTree     *node
	connectTree     *node
	traceTree       *node
	anyTree         *node
	hasCustomMethod bool

	patternMux     *http.ServeMux
	patternMethods map[string]struct{}

	paramsPool sync.Pool
	maxParams  uint16

	// If enabled, adds the matched route path onto the http.Request context
	// before invoking the handler.
	// The matched route path is only added to handlers of routes that were
	// registered when this option was enabled.
	SaveMatchedRoutePath bool

	// If enabled, the router also writes path params to the http.Request via
	// req.SetPathValue so handlers can use req.PathValue in a net/http ServeMux
	// compatible way.
	PopulatePathValues bool

	// If enabled, HEAD requests fall back to GET handlers when no explicit HEAD
	// handler matches the path.
	HandleHEADWithGET bool

	// Enables automatic redirection if the current route can't be matched but a
	// handler for the path with (without) the trailing slash exists.
	// For example if /foo/ is requested but a route only exists for /foo, the
	// client is redirected to /foo with http status code 301 for GET requests
	// and 308 for all other request methods.
	RedirectTrailingSlash bool

	// If enabled, the router tries to fix the current request path, if no
	// handle is registered for it.
	// First superfluous path elements like ../ or // are removed.
	// Afterwards the router does a case-insensitive lookup of the cleaned path.
	// If a handle can be found for this route, the router makes a redirection
	// to the corrected path with status code 301 for GET requests and 308 for
	// all other request methods.
	// For example /FOO and /..//Foo could be redirected to /foo.
	// RedirectTrailingSlash is independent of this option.
	RedirectFixedPath bool

	// If enabled, the router checks if another method is allowed for the
	// current route, if the current request can not be routed.
	// If this is the case, the request is answered with 'Method Not Allowed'
	// and HTTP status code 405.
	// If no other Method is allowed, the request is delegated to the NotFound
	// handler.
	HandleMethodNotAllowed bool

	// If enabled, the router automatically replies to OPTIONS requests.
	// Custom OPTIONS handlers take priority over automatic replies.
	HandleOPTIONS bool

	// An optional http.Handler that is called on automatic OPTIONS requests.
	// The handler is only called if HandleOPTIONS is true and no OPTIONS
	// handler for the specific path was set.
	// The "Allowed" header is set before calling the handler.
	GlobalOPTIONS http.Handler

	// Cached value of global (*) allowed methods
	globalAllowed string

	// Configurable http.Handler which is called when no matching route is
	// found. If it is not set, http.NotFound is used.
	NotFound http.Handler

	// Configurable http.Handler which is called when a request
	// cannot be routed and HandleMethodNotAllowed is true.
	// If it is not set, http.Error with http.StatusMethodNotAllowed is used.
	// The "Allow" header with allowed request methods is set before the handler
	// is called.
	MethodNotAllowed http.Handler

	// Function to handle panics recovered from http handlers.
	// It should be used to generate a error page and return the http error code
	// 500 (Internal Server Error).
	// The handler can be used to keep your server from crashing because of
	// unrecovered panics.
	PanicHandler func(http.ResponseWriter, *http.Request, interface{})
}

// Make sure the Router conforms with the http.Handler interface
var _ http.Handler = New()

// New returns a new initialized Router.
// Path auto-correction, including trailing slashes, is enabled by default.
func New() *Router {
	return &Router{
		RedirectTrailingSlash:  true,
		RedirectFixedPath:      true,
		HandleMethodNotAllowed: true,
		HandleOPTIONS:          true,
	}
}

const anyMethod = ""

const (
	allowBitConnect uint8 = 1 << iota
	allowBitDelete
	allowBitGet
	allowBitHead
	allowBitPatch
	allowBitPost
	allowBitPut
	allowBitTrace
)

var (
	allowedMaskNoOptions   [256]string
	allowedMaskWithOptions [256]string
)

func init() {
	for mask := 1; mask < 256; mask++ {
		allowedMaskNoOptions[mask] = buildAllowedMaskString(uint8(mask), false)
		allowedMaskWithOptions[mask] = buildAllowedMaskString(uint8(mask), true)
	}
}

func buildAllowedMaskString(mask uint8, includeOptions bool) string {
	allowed := make([]string, 0, 9)
	if mask&allowBitConnect != 0 {
		allowed = append(allowed, http.MethodConnect)
	}
	if mask&allowBitDelete != 0 {
		allowed = append(allowed, http.MethodDelete)
	}
	if mask&allowBitGet != 0 {
		allowed = append(allowed, http.MethodGet)
	}
	if mask&allowBitHead != 0 {
		allowed = append(allowed, http.MethodHead)
	}
	if includeOptions {
		allowed = append(allowed, http.MethodOptions)
	}
	if mask&allowBitPatch != 0 {
		allowed = append(allowed, http.MethodPatch)
	}
	if mask&allowBitPost != 0 {
		allowed = append(allowed, http.MethodPost)
	}
	if mask&allowBitPut != 0 {
		allowed = append(allowed, http.MethodPut)
	}
	if mask&allowBitTrace != 0 {
		allowed = append(allowed, http.MethodTrace)
	}
	return strings.Join(allowed, ", ")
}

func allowedFromMask(mask uint8, includeOptions bool) string {
	if includeOptions {
		return allowedMaskWithOptions[mask]
	}
	return allowedMaskNoOptions[mask]
}

func (r *Router) globalAllowedMask() uint8 {
	var mask uint8
	if r.connectTree != nil {
		mask |= allowBitConnect
	}
	if r.deleteTree != nil {
		mask |= allowBitDelete
	}
	if r.getTree != nil {
		mask |= allowBitGet
	}
	if r.headTree != nil {
		mask |= allowBitHead
	}
	if r.patchTree != nil {
		mask |= allowBitPatch
	}
	if r.postTree != nil {
		mask |= allowBitPost
	}
	if r.putTree != nil {
		mask |= allowBitPut
	}
	if r.traceTree != nil {
		mask |= allowBitTrace
	}
	return mask
}

func (r *Router) pathAllowedMask(path, reqMethod string) uint8 {
	var mask uint8

	if root := r.connectTree; root != nil && reqMethod != http.MethodConnect {
		handle, _, _ := root.getValue(path, nil)
		if handle != nil {
			mask |= allowBitConnect
		}
	}
	if root := r.deleteTree; root != nil && reqMethod != http.MethodDelete {
		handle, _, _ := root.getValue(path, nil)
		if handle != nil {
			mask |= allowBitDelete
		}
	}

	hasGet := false
	if root := r.getTree; root != nil {
		handle, _, _ := root.getValue(path, nil)
		if handle != nil {
			hasGet = true
			if reqMethod != http.MethodGet {
				mask |= allowBitGet
			}
		}
	}

	hasHead := false
	if root := r.headTree; root != nil {
		handle, _, _ := root.getValue(path, nil)
		if handle != nil {
			hasHead = true
			if reqMethod != http.MethodHead {
				mask |= allowBitHead
			}
		}
	}
	if r.HandleHEADWithGET && hasGet && !hasHead && reqMethod != http.MethodHead {
		mask |= allowBitHead
	}

	if root := r.patchTree; root != nil && reqMethod != http.MethodPatch {
		handle, _, _ := root.getValue(path, nil)
		if handle != nil {
			mask |= allowBitPatch
		}
	}
	if root := r.postTree; root != nil && reqMethod != http.MethodPost {
		handle, _, _ := root.getValue(path, nil)
		if handle != nil {
			mask |= allowBitPost
		}
	}
	if root := r.putTree; root != nil && reqMethod != http.MethodPut {
		handle, _, _ := root.getValue(path, nil)
		if handle != nil {
			mask |= allowBitPut
		}
	}
	if root := r.traceTree; root != nil && reqMethod != http.MethodTrace {
		handle, _, _ := root.getValue(path, nil)
		if handle != nil {
			mask |= allowBitTrace
		}
	}

	return mask
}

func (r *Router) tree(method string) *node {
	switch method {
	case http.MethodGet:
		return r.getTree
	case http.MethodHead:
		return r.headTree
	case http.MethodPost:
		return r.postTree
	case http.MethodPut:
		return r.putTree
	case http.MethodPatch:
		return r.patchTree
	case http.MethodDelete:
		return r.deleteTree
	case http.MethodOptions:
		return r.optionsTree
	case http.MethodConnect:
		return r.connectTree
	case http.MethodTrace:
		return r.traceTree
	case anyMethod:
		return r.anyTree
	default:
		if r.trees == nil {
			return nil
		}
		return r.trees[method]
	}
}

func (r *Router) setTree(method string, root *node) {
	if r.trees == nil {
		r.trees = make(map[string]*node)
	}
	r.trees[method] = root

	switch method {
	case http.MethodGet:
		r.getTree = root
	case http.MethodHead:
		r.headTree = root
	case http.MethodPost:
		r.postTree = root
	case http.MethodPut:
		r.putTree = root
	case http.MethodPatch:
		r.patchTree = root
	case http.MethodDelete:
		r.deleteTree = root
	case http.MethodOptions:
		r.optionsTree = root
	case http.MethodConnect:
		r.connectTree = root
	case http.MethodTrace:
		r.traceTree = root
	case anyMethod:
		r.anyTree = root
	default:
		r.hasCustomMethod = true
	}
}

func (r *Router) setPathValues(req *http.Request, ps Params) {
	if !r.PopulatePathValues || len(ps) == 0 {
		return
	}

	for _, p := range ps {
		if p.Key == MatchedRoutePathParam {
			continue
		}

		v := p.Value
		if len(v) > 0 && v[0] == '/' {
			v = v[1:]
		}
		req.SetPathValue(p.Key, v)
	}
}

func (r *Router) patternHandlerForRequest(req *http.Request) (http.Handler, bool) {
	if r.patternMux == nil {
		return nil, false
	}

	handler, pattern := r.patternMux.Handler(req)
	if pattern != "" {
		return handler, true
	}

	if len(r.patternMethods) == 0 {
		return nil, false
	}

	probe := *req
	for method := range r.patternMethods {
		if method == req.Method {
			continue
		}
		probe.Method = method
		if _, p := r.patternMux.Handler(&probe); p != "" {
			return handler, true
		}
	}
	return nil, false
}

func (r *Router) getParams() *Params {
	ps, _ := r.paramsPool.Get().(*Params)
	*ps = (*ps)[0:0] // reset slice
	return ps
}

func (r *Router) putParams(ps *Params) {
	if ps != nil {
		r.paramsPool.Put(ps)
	}
}

func (r *Router) saveMatchedRoutePath(path string, handle Handle) Handle {
	return func(w http.ResponseWriter, req *http.Request, ps Params) {
		if ps == nil {
			psp := r.getParams()
			ps = (*psp)[0:1]
			ps[0] = Param{Key: MatchedRoutePathParam, Value: path}
			handle(w, req, ps)
			r.putParams(psp)
		} else {
			ps = append(ps, Param{Key: MatchedRoutePathParam, Value: path})
			handle(w, req, ps)
		}
	}
}

// GET is a shortcut for router.Handle(http.MethodGet, path, handle)
func (r *Router) GET(path string, handle Handle) {
	r.Handle(http.MethodGet, path, handle)
}

// HEAD is a shortcut for router.Handle(http.MethodHead, path, handle)
func (r *Router) HEAD(path string, handle Handle) {
	r.Handle(http.MethodHead, path, handle)
}

// OPTIONS is a shortcut for router.Handle(http.MethodOptions, path, handle)
func (r *Router) OPTIONS(path string, handle Handle) {
	r.Handle(http.MethodOptions, path, handle)
}

// POST is a shortcut for router.Handle(http.MethodPost, path, handle)
func (r *Router) POST(path string, handle Handle) {
	r.Handle(http.MethodPost, path, handle)
}

// PUT is a shortcut for router.Handle(http.MethodPut, path, handle)
func (r *Router) PUT(path string, handle Handle) {
	r.Handle(http.MethodPut, path, handle)
}

// PATCH is a shortcut for router.Handle(http.MethodPatch, path, handle)
func (r *Router) PATCH(path string, handle Handle) {
	r.Handle(http.MethodPatch, path, handle)
}

// DELETE is a shortcut for router.Handle(http.MethodDelete, path, handle)
func (r *Router) DELETE(path string, handle Handle) {
	r.Handle(http.MethodDelete, path, handle)
}

// Handle registers a new request handle with the given path and method.
//
// For GET, POST, PUT, PATCH and DELETE requests the respective shortcut
// functions can be used.
//
// This function is intended for bulk loading and to allow the usage of less
// frequently used, non-standardized or custom methods (e.g. for internal
// communication with a proxy).
func (r *Router) Handle(method, path string, handle Handle) {
	r.handle(method, path, handle, false)
}

func (r *Router) handle(method, path string, handle Handle, allowEmptyMethod bool) {
	varsCount := uint16(0)

	if method == "" && !allowEmptyMethod {
		panic("method must not be empty")
	}
	if len(path) < 1 || path[0] != '/' {
		panic("path must begin with '/' in path '" + path + "'")
	}
	if handle == nil {
		panic("handle must not be nil")
	}

	if r.SaveMatchedRoutePath {
		varsCount++
		handle = r.saveMatchedRoutePath(path, handle)
	}

	root := r.tree(method)
	if root == nil {
		root = new(node)
		r.setTree(method, root)

		r.globalAllowed = r.allowed("*", "")
	}

	root.addRoute(path, handle)

	// Update maxParams
	if paramsCount := countParams(path); paramsCount+varsCount > r.maxParams {
		r.maxParams = paramsCount + varsCount
	}

	// Lazy-init paramsPool alloc func
	if r.paramsPool.New == nil && r.maxParams > 0 {
		r.paramsPool.New = func() interface{} {
			ps := make(Params, 0, r.maxParams)
			return &ps
		}
	}
}

// Handler is an adapter which allows the usage of an http.Handler as a
// request handle.
// The Params are available in the request context under ParamsKey.
func (r *Router) Handler(method, path string, handler http.Handler) {
	r.Handle(method, path,
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

// HandlerFunc is an adapter which allows the usage of an http.HandlerFunc as a
// request handle.
func (r *Router) HandlerFunc(method, path string, handler http.HandlerFunc) {
	r.Handler(method, path, handler)
}

// ServeFiles serves files from the given file system root.
// The path must end with "/*filepath", files are then served from the local
// path /defined/root/dir/*filepath.
// For example if root is "/etc" and *filepath is "passwd", the local file
// "/etc/passwd" would be served.
// Internally a http.FileServer is used, therefore http.NotFound is used instead
// of the Router's NotFound handler.
// To use the operating system's file system implementation,
// use http.Dir:
//
//	router.ServeFiles("/src/*filepath", http.Dir("/var/www"))
func (r *Router) ServeFiles(path string, root http.FileSystem) {
	if len(path) < 10 || path[len(path)-10:] != "/*filepath" {
		panic("path must end with /*filepath in path '" + path + "'")
	}

	fileServer := http.FileServer(root)

	r.GET(path, func(w http.ResponseWriter, req *http.Request, ps Params) {
		req.URL.Path = ps.ByName("filepath")
		fileServer.ServeHTTP(w, req)
	})
}

func (r *Router) recv(w http.ResponseWriter, req *http.Request) {
	if rcv := recover(); rcv != nil {
		r.PanicHandler(w, req, rcv)
	}
}

// Lookup allows the manual lookup of a method + path combo.
// This is e.g. useful to build a framework around this router.
// If the path was found, it returns the handle function and the path parameter
// values. Otherwise the third return value indicates whether a redirection to
// the same path with an extra / without the trailing slash should be performed.
func (r *Router) copyOutParams(ps *Params) Params {
	out := make(Params, len(*ps))
	copy(out, *ps)
	r.putParams(ps)
	return out
}

// ReleaseParams returns borrowed params to the internal pool.
//
// It is intended for use with LookupBorrowed/LookupNoCopy.
func (r *Router) ReleaseParams(ps *Params) {
	r.putParams(ps)
}

// LookupBorrowed is an allocation-optimized variant of Lookup.
//
// On success it may return params borrowed from the router's internal pool.
// Call ReleaseParams when done with the returned params.
func (r *Router) LookupBorrowed(method, path string) (Handle, *Params, bool) {
	if r.trees == nil {
		return nil, nil, false
	}

	anyRoot := r.anyTree
	if anyRoot == nil && !(method == http.MethodHead && r.HandleHEADWithGET) {
		if root := r.tree(method); root != nil {
			handle, ps, tsr := root.getValue(path, r.getParams)
			if handle == nil {
				r.putParams(ps)
				return nil, nil, tsr
			}
			return handle, ps, tsr
		}
		return nil, nil, false
	}

	var tsr bool

	primary := r.tree(method)
	if primary != nil {
		handle, ps, currentTSR := primary.getValue(path, r.getParams)
		if handle != nil {
			return handle, ps, currentTSR
		}
		r.putParams(ps)
		tsr = tsr || currentTSR
	}

	var getRoot *node
	if method == http.MethodHead && r.HandleHEADWithGET {
		getRoot = r.getTree
		if getRoot != nil && getRoot != primary {
			handle, ps, currentTSR := getRoot.getValue(path, r.getParams)
			if handle != nil {
				return handle, ps, currentTSR
			}
			r.putParams(ps)
			tsr = tsr || currentTSR
		}
	}

	if anyRoot != nil && anyRoot != primary && anyRoot != getRoot {
		handle, ps, currentTSR := anyRoot.getValue(path, r.getParams)
		if handle != nil {
			return handle, ps, currentTSR
		}
		r.putParams(ps)
		tsr = tsr || currentTSR
	}

	return nil, nil, tsr
}

// LookupNoCopy is an alias of LookupBorrowed.
func (r *Router) LookupNoCopy(method, path string) (Handle, *Params, bool) {
	return r.LookupBorrowed(method, path)
}

func (r *Router) Lookup(method, path string) (Handle, Params, bool) {
	if r.trees == nil {
		return nil, nil, false
	}

	anyRoot := r.anyTree
	if anyRoot == nil && !(method == http.MethodHead && r.HandleHEADWithGET) {
		if root := r.tree(method); root != nil {
			handle, ps, tsr := root.getValue(path, r.getParams)
			if handle == nil {
				r.putParams(ps)
				return nil, nil, tsr
			}
			if ps == nil {
				return handle, nil, tsr
			}
			return handle, r.copyOutParams(ps), tsr
		}
		return nil, nil, false
	}

	var tsr bool

	primary := r.tree(method)
	if primary != nil {
		handle, ps, currentTSR := primary.getValue(path, r.getParams)
		if handle != nil {
			if ps == nil {
				return handle, nil, currentTSR
			}
			return handle, r.copyOutParams(ps), currentTSR
		}
		r.putParams(ps)
		tsr = tsr || currentTSR
	}

	var getRoot *node
	if method == http.MethodHead && r.HandleHEADWithGET {
		getRoot = r.getTree
		if getRoot != nil && getRoot != primary {
			handle, ps, currentTSR := getRoot.getValue(path, r.getParams)
			if handle != nil {
				if ps == nil {
					return handle, nil, currentTSR
				}
				return handle, r.copyOutParams(ps), currentTSR
			}
			r.putParams(ps)
			tsr = tsr || currentTSR
		}
	}

	if anyRoot != nil && anyRoot != primary && anyRoot != getRoot {
		handle, ps, currentTSR := anyRoot.getValue(path, r.getParams)
		if handle != nil {
			if ps == nil {
				return handle, nil, currentTSR
			}
			return handle, r.copyOutParams(ps), currentTSR
		}
		r.putParams(ps)
		tsr = tsr || currentTSR
	}

	return nil, nil, tsr
}

func (r *Router) allowed(path, reqMethod string) (allow string) {
	if path == "*" { // server-wide
		if reqMethod != "" {
			return r.globalAllowed
		}

		if !r.hasCustomMethod {
			if mask := r.globalAllowedMask(); mask != 0 {
				return allowedFromMask(mask, r.HandleOPTIONS)
			}
			return ""
		}

		allowed := make([]string, 0, 9)
		if r.connectTree != nil {
			allowed = append(allowed, http.MethodConnect)
		}
		if r.deleteTree != nil {
			allowed = append(allowed, http.MethodDelete)
		}
		if r.getTree != nil {
			allowed = append(allowed, http.MethodGet)
		}
		if r.headTree != nil {
			allowed = append(allowed, http.MethodHead)
		}
		if r.patchTree != nil {
			allowed = append(allowed, http.MethodPatch)
		}
		if r.postTree != nil {
			allowed = append(allowed, http.MethodPost)
		}
		if r.putTree != nil {
			allowed = append(allowed, http.MethodPut)
		}
		if r.traceTree != nil {
			allowed = append(allowed, http.MethodTrace)
		}

		for method := range r.trees {
			switch method {
			case anyMethod,
				http.MethodOptions,
				http.MethodConnect,
				http.MethodDelete,
				http.MethodGet,
				http.MethodHead,
				http.MethodPatch,
				http.MethodPost,
				http.MethodPut,
				http.MethodTrace:
				continue
			}
			allowed = append(allowed, method)
		}

		if len(allowed) == 0 {
			return ""
		}
		if r.HandleOPTIONS {
			allowed = append(allowed, http.MethodOptions)
		}
		for i := 1; i < len(allowed); i++ {
			for j := i; j > 0 && allowed[j] < allowed[j-1]; j-- {
				allowed[j], allowed[j-1] = allowed[j-1], allowed[j]
			}
		}
		return strings.Join(allowed, ", ")
	}

	if !r.hasCustomMethod {
		if mask := r.pathAllowedMask(path, reqMethod); mask != 0 {
			return allowedFromMask(mask, r.HandleOPTIONS)
		}
		return ""
	}

	allowed := make([]string, 0, 9)
	if root := r.connectTree; root != nil && reqMethod != http.MethodConnect {
		handle, _, _ := root.getValue(path, nil)
		if handle != nil {
			allowed = append(allowed, http.MethodConnect)
		}
	}
	if root := r.deleteTree; root != nil && reqMethod != http.MethodDelete {
		handle, _, _ := root.getValue(path, nil)
		if handle != nil {
			allowed = append(allowed, http.MethodDelete)
		}
	}

	hasGet := false
	if root := r.getTree; root != nil {
		handle, _, _ := root.getValue(path, nil)
		if handle != nil {
			hasGet = true
			if reqMethod != http.MethodGet {
				allowed = append(allowed, http.MethodGet)
			}
		}
	}

	hasHead := false
	if root := r.headTree; root != nil {
		handle, _, _ := root.getValue(path, nil)
		if handle != nil {
			hasHead = true
			if reqMethod != http.MethodHead {
				allowed = append(allowed, http.MethodHead)
			}
		}
	}
	if r.HandleHEADWithGET && hasGet && !hasHead && reqMethod != http.MethodHead {
		allowed = append(allowed, http.MethodHead)
	}

	if root := r.patchTree; root != nil && reqMethod != http.MethodPatch {
		handle, _, _ := root.getValue(path, nil)
		if handle != nil {
			allowed = append(allowed, http.MethodPatch)
		}
	}
	if root := r.postTree; root != nil && reqMethod != http.MethodPost {
		handle, _, _ := root.getValue(path, nil)
		if handle != nil {
			allowed = append(allowed, http.MethodPost)
		}
	}
	if root := r.putTree; root != nil && reqMethod != http.MethodPut {
		handle, _, _ := root.getValue(path, nil)
		if handle != nil {
			allowed = append(allowed, http.MethodPut)
		}
	}
	if root := r.traceTree; root != nil && reqMethod != http.MethodTrace {
		handle, _, _ := root.getValue(path, nil)
		if handle != nil {
			allowed = append(allowed, http.MethodTrace)
		}
	}

	for method, root := range r.trees {
		switch method {
		case anyMethod,
			http.MethodOptions,
			http.MethodConnect,
			http.MethodDelete,
			http.MethodGet,
			http.MethodHead,
			http.MethodPatch,
			http.MethodPost,
			http.MethodPut,
			http.MethodTrace:
			continue
		}
		if method == reqMethod {
			continue
		}
		handle, ps, _ := root.getValue(path, nil)
		if handle != nil {
			allowed = append(allowed, method)
		}
		r.putParams(ps)
	}

	if len(allowed) == 0 {
		return ""
	}
	if r.HandleOPTIONS {
		allowed = append(allowed, http.MethodOptions)
	}
	for i := 1; i < len(allowed); i++ {
		for j := i; j > 0 && allowed[j] < allowed[j-1]; j-- {
			allowed[j], allowed[j-1] = allowed[j-1], allowed[j]
		}
	}
	return strings.Join(allowed, ", ")
}

// ServeHTTP makes the router implement the http.Handler interface.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if r.PanicHandler != nil {
		defer r.recv(w, req)
	}

	if r.patternMux != nil {
		if patternHandler, ok := r.patternHandlerForRequest(req); ok {
			patternHandler.ServeHTTP(w, req)
			return
		}
	}

	path := req.URL.Path
	method := req.Method

	if r.trees != nil {
		anyRoot := r.anyTree

		// Fast path: no any-method routes and no HEAD->GET fallback.
		if anyRoot == nil && !(method == http.MethodHead && r.HandleHEADWithGET) {
			if root := r.tree(method); root != nil {
				if handle, ps, tsr := root.getValue(path, r.getParams); handle != nil {
					if ps != nil {
						r.setPathValues(req, *ps)
						handle(w, req, *ps)
						r.putParams(ps)
					} else {
						handle(w, req, nil)
					}
					return
				} else {
					r.putParams(ps)

					if method != http.MethodConnect && path != "/" {
						// Moved Permanently, request with GET method
						code := http.StatusMovedPermanently
						if method != http.MethodGet {
							// Permanent Redirect, request with same method
							code = http.StatusPermanentRedirect
						}

						if tsr && r.RedirectTrailingSlash {
							if len(path) > 1 && path[len(path)-1] == '/' {
								req.URL.Path = path[:len(path)-1]
							} else {
								req.URL.Path = path + "/"
							}
							http.Redirect(w, req, req.URL.String(), code)
							return
						}

						// Try to fix the request path
						if r.RedirectFixedPath {
							fixedPath, found := root.findCaseInsensitivePath(
								CleanPath(path),
								r.RedirectTrailingSlash,
							)
							if found {
								req.URL.Path = fixedPath
								http.Redirect(w, req, req.URL.String(), code)
								return
							}
						}
					}
				}
			}
		} else {
			var (
				tsr         bool
				primaryRoot *node
				getRoot     *node
				fallbackAny *node
			)

			primaryRoot = r.tree(method)
			if primaryRoot != nil {
				handle, ps, currentTSR := primaryRoot.getValue(path, r.getParams)
				if handle != nil {
					if ps != nil {
						r.setPathValues(req, *ps)
						handle(w, req, *ps)
						r.putParams(ps)
					} else {
						handle(w, req, nil)
					}
					return
				}
				r.putParams(ps)
				tsr = tsr || currentTSR
			}

			if method == http.MethodHead && r.HandleHEADWithGET {
				getRoot = r.getTree
				if getRoot == primaryRoot {
					getRoot = nil
				}
				if getRoot != nil {
					handle, ps, currentTSR := getRoot.getValue(path, r.getParams)
					if handle != nil {
						if ps != nil {
							r.setPathValues(req, *ps)
							handle(w, req, *ps)
							r.putParams(ps)
						} else {
							handle(w, req, nil)
						}
						return
					}
					r.putParams(ps)
					tsr = tsr || currentTSR
				}
			}

			fallbackAny = anyRoot
			if fallbackAny == primaryRoot || fallbackAny == getRoot {
				fallbackAny = nil
			}
			if fallbackAny != nil {
				handle, ps, currentTSR := fallbackAny.getValue(path, r.getParams)
				if handle != nil {
					if ps != nil {
						r.setPathValues(req, *ps)
						handle(w, req, *ps)
						r.putParams(ps)
					} else {
						handle(w, req, nil)
					}
					return
				}
				r.putParams(ps)
				tsr = tsr || currentTSR
			}

			if (primaryRoot != nil || getRoot != nil || fallbackAny != nil) && method != http.MethodConnect && path != "/" {
				// Moved Permanently, request with GET method
				code := http.StatusMovedPermanently
				if method != http.MethodGet {
					// Permanent Redirect, request with same method
					code = http.StatusPermanentRedirect
				}

				if tsr && r.RedirectTrailingSlash {
					if len(path) > 1 && path[len(path)-1] == '/' {
						req.URL.Path = path[:len(path)-1]
					} else {
						req.URL.Path = path + "/"
					}
					http.Redirect(w, req, req.URL.String(), code)
					return
				}

				// Try to fix the request path
				if r.RedirectFixedPath {
					cleanPath := CleanPath(path)

					if primaryRoot != nil {
						if fixedPath, found := primaryRoot.findCaseInsensitivePath(cleanPath, r.RedirectTrailingSlash); found {
							req.URL.Path = fixedPath
							http.Redirect(w, req, req.URL.String(), code)
							return
						}
					}

					if getRoot != nil {
						if fixedPath, found := getRoot.findCaseInsensitivePath(cleanPath, r.RedirectTrailingSlash); found {
							req.URL.Path = fixedPath
							http.Redirect(w, req, req.URL.String(), code)
							return
						}
					}

					if fallbackAny != nil {
						if fixedPath, found := fallbackAny.findCaseInsensitivePath(cleanPath, r.RedirectTrailingSlash); found {
							req.URL.Path = fixedPath
							http.Redirect(w, req, req.URL.String(), code)
							return
						}
					}
				}
			}
		}
	}

	if method == http.MethodOptions && r.HandleOPTIONS {
		// Handle OPTIONS requests
		if allow := r.allowed(path, http.MethodOptions); allow != "" {
			w.Header().Set("Allow", allow)
			if r.GlobalOPTIONS != nil {
				r.GlobalOPTIONS.ServeHTTP(w, req)
			}
			return
		}
	} else if r.HandleMethodNotAllowed { // Handle 405
		if allow := r.allowed(path, method); allow != "" {
			w.Header().Set("Allow", allow)
			if r.MethodNotAllowed != nil {
				r.MethodNotAllowed.ServeHTTP(w, req)
			} else {
				http.Error(w,
					http.StatusText(http.StatusMethodNotAllowed),
					http.StatusMethodNotAllowed,
				)
			}
			return
		}
	}

	// Handle 404
	if r.NotFound != nil {
		r.NotFound.ServeHTTP(w, req)
	} else {
		http.NotFound(w, req)
	}
}
