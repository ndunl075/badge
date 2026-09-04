// Package policy maps verdicts to allow, deny or log-only.
//
// A policy is data, never code. There is no expression language and nothing is
// evaluated, so a policy can be reviewed, diffed and linted like any other
// configuration. Some rules become inexpressible; that is the intended trade.
package policy

import (
	"fmt"
	"regexp"
	"strings"
)

// Route is a compiled route pattern: an optional method set plus a path glob.
//
// Glob semantics follow what people expect from route tables rather than from
// shell globbing:
//
//   - matches within one path segment
//     **  matches across segments
//     ?   matches a single character within a segment
//     a trailing /** also matches the prefix itself, so /docs/** covers /docs
type Route struct {
	Source  string
	methods map[string]bool
	path    *regexp.Regexp
}

var methodPattern = regexp.MustCompile(`^[A-Za-z|*]+$`)

// CompileRoute turns a pattern such as `GET /docs/**` into a matcher.
func CompileRoute(pattern string) (*Route, error) {
	trimmed := strings.TrimSpace(pattern)
	if trimmed == "" {
		return nil, fmt.Errorf("route pattern is empty")
	}

	methodPart, pathPart := "", trimmed
	if space := strings.Index(trimmed, " "); space != -1 {
		methodPart = trimmed[:space]
		pathPart = strings.TrimSpace(trimmed[space+1:])
	}
	if methodPart != "" && !methodPattern.MatchString(methodPart) {
		return nil, fmt.Errorf("invalid method in route pattern: %s", methodPart)
	}
	if !strings.HasPrefix(pathPart, "/") {
		return nil, fmt.Errorf(`route path must start with "/": %s`, pathPart)
	}

	route := &Route{Source: trimmed}
	if methodPart != "" && methodPart != "*" {
		route.methods = map[string]bool{}
		for _, method := range strings.Split(strings.ToUpper(methodPart), "|") {
			if method != "" {
				route.methods[method] = true
			}
		}
	}

	expr, err := globToRegexp(pathPart)
	if err != nil {
		return nil, err
	}
	route.path = expr
	return route, nil
}

// Matches reports whether a method and path satisfy the pattern.
func (r *Route) Matches(method, path string) bool {
	if r.methods != nil && !r.methods[strings.ToUpper(method)] {
		return false
	}
	return r.path.MatchString(path)
}

func globToRegexp(glob string) (*regexp.Regexp, error) {
	var out strings.Builder
	out.WriteByte('^')
	for i := 0; i < len(glob); {
		c := glob[i]
		if c == '*' && i+1 < len(glob) && glob[i+1] == '*' {
			// A trailing "/**" also matches the prefix with no trailing slash,
			// so "/docs/**" covers "/docs" as well as "/docs/a".
			current := out.String()
			if strings.HasSuffix(current, "/") && i+2 == len(glob) {
				out.Reset()
				out.WriteString(strings.TrimSuffix(current, "/"))
				out.WriteString("(?:/.*)?")
			} else {
				out.WriteString(".*")
			}
			i += 2
			continue
		}
		switch c {
		case '*':
			out.WriteString("[^/]*")
		case '?':
			out.WriteString("[^/]")
		default:
			out.WriteString(regexp.QuoteMeta(string(c)))
		}
		i++
	}
	out.WriteByte('$')
	return regexp.Compile(out.String())
}
