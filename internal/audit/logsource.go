package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// sshSource reads the audit log from the control plane nodes over ssh. It
// needs an account that can read the log file (through sudo by default) and
// key-based, non-interactive authentication.
type sshSource struct {
	hosts   []string
	sshOpts []string
	sudo    bool
	path    string
	offsets map[string]int64
}

func (s *sshSource) Describe() string {
	return fmt.Sprintf("ssh %s:%s", strings.Join(s.hosts, ","), s.path)
}

func (s *sshSource) run(ctx context.Context, host, script string) ([]byte, error) {
	args := append([]string{}, s.sshOpts...)
	args = append(args, host)
	if s.sudo {
		args = append(args, "sudo")
	}
	args = append(args, "sh", "-c", shellQuote(script))
	cmd := exec.CommandContext(ctx, "ssh", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ssh %s: %w: %s", host, err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Begin records the current size of the log on every host.
func (s *sshSource) Begin(ctx context.Context) error {
	for _, h := range s.hosts {
		out, err := s.run(ctx, h, fmt.Sprintf("stat -c %%s %s 2>/dev/null || echo 0", s.path))
		if err != nil {
			return err
		}
		n, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
		if err != nil {
			return fmt.Errorf("%s: unexpected stat output %q", h, out)
		}
		s.offsets[h] = n
	}
	return nil
}

func (s *sshSource) Fetch(ctx context.Context) ([]*Event, error) {
	var all []*Event
	dir := filepath.Dir(s.path)
	for _, h := range s.hosts {
		off := s.offsets[h]
		// If the file was rotated since Begin, fall back to everything in the
		// directory; the caller filters by timestamp anyway.
		script := fmt.Sprintf(
			"size=$(stat -c %%s %s 2>/dev/null || echo 0); if [ \"$size\" -ge %d ]; then tail -c +%d %s; else cat %s/*.log; fi",
			s.path, off, off+1, s.path, dir)
		out, err := s.run(ctx, h, script)
		if err != nil {
			return nil, err
		}
		evs, err := ParseEvents(out, h)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", h, err)
		}
		all = append(all, evs...)
	}
	return all, nil
}

// ParseEvents parses a chunk of audit log into events, skipping anything
// that is not a JSON object (a partial first line, a rotation marker).
func ParseEvents(raw []byte, host string) ([]*Event, error) {
	var out []*Event
	for _, line := range bytes.Split(raw, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		// The first line of a tail -c may be a partial line if the offset
		// landed mid-event (it cannot, offsets are taken at line boundaries
		// because the apiserver writes whole lines, but be defensive).
		if line[0] != '{' {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		e.Raw = string(line)
		e.Host = shortHost(host)
		out = append(out, &e)
	}
	return out, nil
}

func shortHost(h string) string {
	if i := strings.Index(h, "@"); i >= 0 {
		h = h[i+1:]
	}
	return h
}

func groupKey(g string) string {
	if g == "" {
		return "core"
	}
	return g
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
