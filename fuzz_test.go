// Copyright 2026 The HttpRouter Authors.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package httprouter

import (
	"strings"
	"testing"
)

func FuzzCleanPathIdempotent(f *testing.F) {
	seeds := []string{
		"",
		"/",
		"/abc",
		"/abc/",
		"/abc//def",
		"/../abc",
		"/a/b/../c",
		"/u/äpfêl/",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, path string) {
		if len(path) > 4096 {
			t.Skip()
		}

		cleaned := CleanPath(path)
		if len(cleaned) == 0 || cleaned[0] != '/' {
			t.Fatalf("CleanPath(%q) = %q, expected absolute path", path, cleaned)
		}

		if strings.Contains(cleaned, "//") {
			t.Fatalf("CleanPath(%q) = %q, contains double slash", path, cleaned)
		}

		if recleaned := CleanPath(cleaned); recleaned != cleaned {
			t.Fatalf("CleanPath not idempotent: input=%q cleaned=%q recleaned=%q", path, cleaned, recleaned)
		}
	})
}

func FuzzTreeDuplicateRoutePanics(f *testing.F) {
	seeds := []string{
		"/",
		"/a",
		"/a/b",
		"/users/:id",
		"/files/*filepath",
		"/user_:name",
		"/cmd/:tool/:sub",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, path string) {
		if len(path) == 0 || path[0] != '/' || len(path) > 512 {
			t.Skip()
		}

		tree := &node{}
		handle := fakeHandler(path)

		if recv := catchPanic(func() {
			tree.addRoute(path, handle)
		}); recv != nil {
			t.Skip()
		}

		if recv := catchPanic(func() {
			tree.addRoute(path, handle)
		}); recv == nil {
			t.Fatalf("adding duplicate route did not panic for %q", path)
		}
	})
}

func FuzzTreeFindCaseInsensitivePathInvariants(f *testing.F) {
	tree := mustBuildFuzzCaseInsensitiveTree()

	f.Add("/HI", false)
	f.Add("/HI/", true)
	f.Add("/users/Gopher", false)
	f.Add("/SRC/JS/APP.JS", false)
	f.Add("/u/ÄPFÊL/", false)
	f.Add("/u/ÄPFÊL", true)

	f.Fuzz(func(t *testing.T, path string, fixTrailingSlash bool) {
		if len(path) == 0 || path[0] != '/' || len(path) > 1024 {
			t.Skip()
		}

		out, found := tree.findCaseInsensitivePath(path, fixTrailingSlash)
		if !found {
			return
		}

		if len(out) == 0 || out[0] != '/' {
			t.Fatalf("resolved path %q is not absolute", out)
		}
	})
}

func mustBuildFuzzCaseInsensitiveTree() *node {
	tree := &node{}
	routes := []string{
		"/hi",
		"/b/",
		"/users/:name",
		"/cmd/:tool/",
		"/src/*filepath",
		"/x/y",
		"/aa",
		"/a/",
		"/Π",
		"/u/äpfêl/",
		"/u/öpfêl",
	}

	for _, route := range routes {
		if recv := catchPanic(func() {
			tree.addRoute(route, fakeHandler(route))
		}); recv != nil {
			panic("failed to build fuzz tree")
		}
	}

	return tree
}
