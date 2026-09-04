package policy

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/ndunl075/badge/sidecar/wba"
	"gopkg.in/yaml.v3"
)

// Action is what a rule does.
type Action string

const (
	ActionAllow   Action = "allow"
	ActionDeny    Action = "deny"
	ActionLogOnly Action = "log-only"
)

// StringList accepts either a single value or a list, so a condition can be
// written `class: untrusted` or `class: [untrusted, malformed]`.
type StringList []string

func (l *StringList) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		var single string
		if err := node.Decode(&single); err != nil {
			return err
		}
		*l = StringList{single}
		return nil
	}
	var many []string
	if err := node.Decode(&many); err != nil {
		return err
	}
	*l = many
	return nil
}

// Condition matches a verdict. Fields are ANDed; values within a field are ORed.
//
// Class is usually the right field to match on: status alone cannot tell a
// forged signature from a directory timeout.
type Condition struct {
	Status   StringList `yaml:"status"`
	Class    StringList `yaml:"class"`
	Reason   StringList `yaml:"reason"`
	Operator StringList `yaml:"operator"`
	Origin   StringList `yaml:"origin"`
}

// Rule is one entry in an ordered list. First match wins.
type Rule struct {
	ID     string     `yaml:"id"`
	Action Action     `yaml:"action"`
	When   *Condition `yaml:"when"`
	Routes []string   `yaml:"routes"`
}

// Policy is the whole document.
type Policy struct {
	Version   int                 `yaml:"version"`
	Default   Action              `yaml:"default"`
	Operators map[string][]string `yaml:"operators"`
	Rules     []Rule              `yaml:"rules"`
}

// Decision is what the engine returns.
type Decision struct {
	Action   Action
	RuleID   string
	Operator string
	Verdict  wba.Verdict
}

// DefaultPolicy observes and reports; it denies nothing. An operator earns the
// confidence to enforce by reading their own decision log, not by trusting a
// default someone else chose for their traffic.
var DefaultPolicy = Policy{Version: 1, Default: ActionLogOnly}

// Parse validates a YAML or JSON policy document.
//
// Strict on purpose: an unknown key is an error, not a shrug. A typo in
// `action` that silently falls through to the default is the worst possible
// failure — the policy looks like it is enforcing and is not.
func Parse(source []byte) (*Policy, error) {
	decoder := yaml.NewDecoder(strings.NewReader(string(source)))
	decoder.KnownFields(true)

	var doc Policy
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("policy is not valid YAML or JSON: %w", err)
	}
	if doc.Version != 1 {
		return nil, fmt.Errorf("version must be 1")
	}
	if err := validAction(doc.Default, "default"); err != nil {
		return nil, err
	}

	for label, origins := range doc.Operators {
		for i, origin := range origins {
			normalized, err := validOrigin(origin)
			if err != nil {
				return nil, fmt.Errorf("operators.%s[%d]: %w", label, i, err)
			}
			doc.Operators[label][i] = normalized
		}
	}

	seen := map[string]bool{}
	for i, rule := range doc.Rules {
		where := fmt.Sprintf("rules[%d]", i)
		if strings.TrimSpace(rule.ID) == "" {
			return nil, fmt.Errorf("%s.id must be a non-empty string", where)
		}
		if seen[rule.ID] {
			return nil, fmt.Errorf("%s.id: duplicate rule id: %s", where, rule.ID)
		}
		seen[rule.ID] = true
		if err := validAction(rule.Action, where+".action"); err != nil {
			return nil, err
		}
		if rule.When != nil {
			if err := validCondition(rule.When, doc.Operators, where+".when"); err != nil {
				return nil, err
			}
		}
		for j, route := range rule.Routes {
			if _, err := CompileRoute(route); err != nil {
				return nil, fmt.Errorf("%s.routes[%d]: %w", where, j, err)
			}
		}
	}
	return &doc, nil
}

func validAction(action Action, where string) error {
	switch action {
	case ActionAllow, ActionDeny, ActionLogOnly:
		return nil
	}
	return fmt.Errorf("%s must be one of allow, deny, log-only", where)
}

// validOrigin insists origins are written literally. An origin with a trailing
// slash never matches a normalized one, producing a policy that looks right and
// does nothing.
func validOrigin(origin string) (string, error) {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("origin must be an absolute https URL: %s", origin)
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("origin must use https: %s", origin)
	}
	if parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("origin must have no path, query or trailing slash: %s", origin)
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

func validCondition(c *Condition, operators map[string][]string, where string) error {
	if len(c.Status) == 0 && len(c.Class) == 0 && len(c.Reason) == 0 &&
		len(c.Operator) == 0 && len(c.Origin) == 0 {
		return fmt.Errorf("%s: condition must constrain something", where)
	}
	for _, status := range c.Status {
		switch wba.Status(status) {
		case wba.StatusVerified, wba.StatusClaimed, wba.StatusUnknown:
		default:
			return fmt.Errorf("%s.status: unknown value %q", where, status)
		}
	}
	for _, class := range c.Class {
		switch wba.Class(class) {
		case wba.ClassOK, wba.ClassAbsent, wba.ClassMalformed, wba.ClassExpired,
			wba.ClassUntrusted, wba.ClassUnverifiable:
		default:
			return fmt.Errorf("%s.class: unknown value %q", where, class)
		}
	}
	for _, reason := range c.Reason {
		known := false
		for _, candidate := range wba.AllReasons() {
			if string(candidate) == reason {
				known = true
				break
			}
		}
		if !known {
			return fmt.Errorf("%s.reason: unknown reason code %q", where, reason)
		}
	}
	for _, label := range c.Operator {
		if _, ok := operators[label]; !ok {
			return fmt.Errorf("%s.operator: unknown operator %q", where, label)
		}
	}
	for i, origin := range c.Origin {
		normalized, err := validOrigin(origin)
		if err != nil {
			return fmt.Errorf("%s.origin[%d]: %w", where, i, err)
		}
		c.Origin[i] = normalized
	}
	return nil
}

type compiledRule struct {
	rule   Rule
	routes []*Route
}

// Engine evaluates a policy with its routes compiled once.
//
// Compiling globs per request would put a regex build on the hot path of every
// request the server handles, signed or not.
type Engine struct {
	policy   Policy
	rules    []compiledRule
	byOrigin map[string]string
}

func Compile(p Policy) (*Engine, error) {
	engine := &Engine{policy: p, byOrigin: map[string]string{}}
	for i, rule := range p.Rules {
		compiled := compiledRule{rule: rule}
		for _, pattern := range rule.Routes {
			route, err := CompileRoute(pattern)
			if err != nil {
				return nil, fmt.Errorf("rules[%d].routes: %w", i, err)
			}
			compiled.routes = append(compiled.routes, route)
		}
		engine.rules = append(engine.rules, compiled)
	}
	for label, origins := range p.Operators {
		for _, origin := range origins {
			// An origin listed under two operators keeps the first label; the
			// linter reports the overlap.
			if _, seen := engine.byOrigin[origin]; !seen {
				engine.byOrigin[origin] = label
			}
		}
	}
	return engine, nil
}

// Evaluate applies the policy. The implicit default is reported as the rule id
// "default" rather than as a blank.
func (e *Engine) Evaluate(verdict wba.Verdict, method, path string) Decision {
	operator := e.byOrigin[verdict.SignatureAgent]

	for _, compiled := range e.rules {
		if len(compiled.routes) > 0 && !anyRouteMatches(compiled.routes, method, path) {
			continue
		}
		if compiled.rule.When != nil && !matches(compiled.rule.When, verdict, operator) {
			continue
		}
		return Decision{Action: compiled.rule.Action, RuleID: compiled.rule.ID, Operator: operator, Verdict: verdict}
	}
	return Decision{Action: e.policy.Default, RuleID: "default", Operator: operator, Verdict: verdict}
}

func anyRouteMatches(routes []*Route, method, path string) bool {
	for _, route := range routes {
		if route.Matches(method, path) {
			return true
		}
	}
	return false
}

func matches(c *Condition, verdict wba.Verdict, operator string) bool {
	if len(c.Status) > 0 && !containsString(c.Status, string(verdict.Status)) {
		return false
	}
	if len(c.Class) > 0 && !containsString(c.Class, string(verdict.Class)) {
		return false
	}
	if len(c.Reason) > 0 && !containsString(c.Reason, string(verdict.Reason)) {
		return false
	}
	if len(c.Operator) > 0 && (operator == "" || !containsString(c.Operator, operator)) {
		return false
	}
	if len(c.Origin) > 0 && (verdict.SignatureAgent == "" || !containsString(c.Origin, verdict.SignatureAgent)) {
		return false
	}
	return true
}

func containsString(list StringList, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
