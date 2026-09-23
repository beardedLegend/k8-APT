package auditpolicy

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Annotated is a rule with the comment lines written above it.
type Annotated struct {
	Rule     Rule
	Comments []string
}

// flow renders a string list as a YAML flow sequence. JSON string syntax is
// valid YAML, and it quotes whatever needs quoting ("", "*", ":").
func flow(list []string) string {
	b, _ := json.Marshal(list)
	return strings.ReplaceAll(string(b), `","`, `", "`)
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// Render writes rules as list items of a policy's rules, each item indented
// by indent.
func Render(rules []Annotated, indent string) string {
	var b strings.Builder
	line := func(depth string, format string, args ...any) {
		b.WriteString(indent + depth + fmt.Sprintf(format, args...) + "\n")
	}
	for i, a := range rules {
		if i > 0 {
			b.WriteString("\n")
		}
		for _, c := range a.Comments {
			line("", "# %s", c)
		}
		r := a.Rule
		line("", "- level: %s", r.Level)
		if len(r.Users) > 0 {
			line("  ", "users: %s", flow(r.Users))
		}
		if len(r.UserGroups) > 0 {
			line("  ", "userGroups: %s", flow(r.UserGroups))
		}
		if len(r.Verbs) > 0 {
			line("  ", "verbs: %s", flow(r.Verbs))
		}
		if len(r.Namespaces) > 0 {
			line("  ", "namespaces: %s", flow(r.Namespaces))
		}
		if len(r.Resources) > 0 {
			line("  ", "resources:")
			for _, gr := range r.Resources {
				line("    ", "- group: %s", quote(gr.Group))
				if len(gr.Resources) > 0 {
					line("      ", "resources: %s", flow(gr.Resources))
				}
				if len(gr.ResourceNames) > 0 {
					line("      ", "resourceNames: %s", flow(gr.ResourceNames))
				}
			}
		}
		if len(r.NonResourceURLs) > 0 {
			line("  ", "nonResourceURLs: %s", flow(r.NonResourceURLs))
		}
		if len(r.OmitStages) > 0 {
			line("  ", "omitStages: %s", flow(r.OmitStages))
		}
	}
	return b.String()
}

// Splice inserts rules at the top of the rules of an existing policy file,
// ahead of every original rule, so that they win under first-match. The rest
// of the file — comments included — is kept as it is. header lines are
// written as comments above the inserted rules. With omitManagedFields the
// top-level field is set to true.
func Splice(original []byte, header []string, rules []Annotated, omitManagedFields bool) ([]byte, error) {
	orig, err := Parse(original)
	if err != nil {
		return nil, fmt.Errorf("the policy to extend: %w", err)
	}
	lines := strings.Split(string(original), "\n")
	at := -1
	for i, l := range lines {
		t := strings.TrimRight(l, " \t\r")
		if t == "rules:" || t == "rules: []" {
			at = i
			break
		}
	}
	if at < 0 {
		lines = append(lines, "rules:")
		at = len(lines) - 1
	}
	lines[at] = "rules:"
	indent := "  "
	for _, l := range lines[at+1:] {
		t := strings.TrimLeft(l, " ")
		if strings.HasPrefix(t, "- ") {
			indent = l[:len(l)-len(t)]
			break
		}
	}

	var block strings.Builder
	block.WriteString("\n")
	for _, h := range header {
		block.WriteString(indent + "# " + h + "\n")
	}
	if len(header) > 0 {
		block.WriteString("\n")
	}
	block.WriteString(Render(rules, indent))
	block.WriteString("\n" + indent + "# ---- the original rules follow, unchanged ----\n")

	out := append([]string{}, lines[:at+1]...)
	out = append(out, strings.Split(strings.TrimSuffix(block.String(), "\n"), "\n")...)
	out = append(out, lines[at+1:]...)

	if omitManagedFields {
		set := false
		for i, l := range out {
			if strings.HasPrefix(l, "omitManagedFields:") {
				out[i] = "omitManagedFields: true"
				set = true
				break
			}
		}
		if !set {
			for i, l := range out {
				if l == "rules:" {
					ins := []string{"# Added by k8-apt: managedFields are large, machine-generated and never", "# evidence.", "omitManagedFields: true", ""}
					out = append(out[:i], append(ins, out[i:]...)...)
					break
				}
			}
		}
	}

	result := []byte(strings.Join(out, "\n"))
	got, err := Parse(result)
	if err != nil {
		return nil, fmt.Errorf("the generated policy does not parse: %w", err)
	}
	if len(got.Rules) != len(orig.Rules)+len(rules) {
		return nil, fmt.Errorf("the generated policy has %d rules, want %d", len(got.Rules), len(orig.Rules)+len(rules))
	}
	return result, nil
}
