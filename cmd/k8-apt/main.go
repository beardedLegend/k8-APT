// Command k8-apt exercises a Kubernetes cluster with the requests a real day
// produces — and with the ones an attacker would make — then reads the
// API server's audit log and reports what the audit policy actually recorded.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/beardedLegend/k8-apt/internal/config"
	"github.com/beardedLegend/k8-apt/internal/policygen"
	"github.com/beardedLegend/k8-apt/internal/report"
	"github.com/beardedLegend/k8-apt/internal/runner"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

const usage = `k8-apt — Kubernetes audit policy tester

  k8-apt run [flags]        run the scenarios against a cluster and report
  k8-apt scenarios [flags]  list the scenarios that apply to a profile
  k8-apt config [flags]     print the effective cluster profile
  k8-apt version            print the version

Run "k8-apt <command> -h" for the flags of a command.

A run creates a throw-away namespace and a handful of uniquely named
cluster-scoped objects, makes requests as itself and as service accounts it
creates, and deletes all of it again. It needs cluster-admin on the cluster
and read access to the API server's audit log (over ssh to the control plane
nodes by default).
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "run":
		err = runCmd(ctx, os.Args[2:])
	case "scenarios":
		err = scenariosCmd(os.Args[2:])
	case "config":
		err = configCmd(os.Args[2:])
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "k8-apt: %v\n", err)
		os.Exit(1)
	}
}

// commonFlags are shared by every command that loads a profile.
type commonFlags struct {
	config     string
	kubeconfig string
}

func (f *commonFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.config, "config", "", "cluster profile (YAML); defaults apply when unset")
	fs.StringVar(&f.kubeconfig, "kubeconfig", "", "kubeconfig to use (default $KUBECONFIG, then ~/.kube/config)")
}

func (f *commonFlags) load() (*config.Cluster, error) {
	cfg, err := config.Load(f.config)
	if err != nil {
		return nil, err
	}
	if f.kubeconfig != "" {
		cfg.Kubeconfig = f.kubeconfig
	}
	return cfg, nil
}

func runCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var common commonFlags
	common.register(fs)
	var (
		strict     = fs.Bool("strict", false, "fail the run on any difference from the baseline policy, not only on invariants")
		idle       = fs.Duration("idle-sample", 0, "idle this long before acting, to measure the cluster's background log volume (e.g. 10m)")
		only       = fs.String("only", "", "comma-separated substrings; run only the scenarios whose name matches")
		logFiles   = fs.String("log-files", "", "comma-separated local audit log files to verify against, instead of reading the cluster")
		budgetGB   = fs.Float64("budget", 0, "log volume budget in GB per cluster per year (default from the profile)")
		eventsFile = fs.String("events-file", "", "write every audit event of the run to this file (JSON lines)")
		reportFile = fs.String("report", "", "write the full report as markdown to this file")
		jsonOut    = fs.Bool("json", false, "print the results as JSON instead of the terminal report")
		color      = fs.String("color", "auto", "colorise the terminal report: auto, always or never")
		quiet      = fs.Bool("quiet", false, "do not print progress while the scenarios run")
		genPolicy  = fs.String("generate-policy", "", "write an audit policy that fixes the findings of the run to this file")
		policyFile = fs.String("policy", "", "the audit policy the cluster runs, extended by --generate-policy (default: policy/baseline.yaml)")
		fixWhat    = fs.String("fix", "fail,diff,gap", "which findings --generate-policy acts on: any of fail, diff, gap")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := common.load()
	if err != nil {
		return err
	}
	if *idle > 0 {
		cfg.IdleSample = config.Duration(*idle)
	}
	if *budgetGB > 0 {
		cfg.Budget.GBPerYear = *budgetGB
	}
	if *logFiles != "" {
		cfg.Log.Type = "files"
		cfg.Log.Files = strings.Split(*logFiles, ",")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	var current []byte
	if *genPolicy != "" {
		for _, f := range strings.Split(*fixWhat, ",") {
			switch strings.ToLower(strings.TrimSpace(f)) {
			case "fail", "diff", "gap":
			default:
				return fmt.Errorf("--fix: %q is not one of fail, diff, gap", f)
			}
		}
		if *policyFile != "" {
			if current, err = os.ReadFile(*policyFile); err != nil {
				return err
			}
		}
	} else if *policyFile != "" {
		return fmt.Errorf("--policy only makes sense with --generate-policy")
	}
	switch *color {
	case "always":
		t := true
		report.SetColor(&t)
	case "never":
		f := false
		report.SetColor(&f)
	case "auto":
	default:
		return fmt.Errorf("--color: want auto, always or never")
	}

	opt := runner.Options{
		Strict:     *strict,
		EventsFile: *eventsFile,
		ReportFile: *reportFile,
	}
	if *only != "" {
		opt.Only = strings.Split(*only, ",")
	}
	if !*quiet && !*jsonOut {
		opt.Log = func(format string, args ...any) { fmt.Printf(format+"\n", args...) }
	}

	started := time.Now()
	res, err := runner.Run(ctx, cfg, opt)
	if err != nil {
		return err
	}
	if *jsonOut {
		if err := printJSON(res, opt, started); err != nil {
			return err
		}
	} else {
		runner.Report(res)
	}
	if *genPolicy != "" {
		plan, err := policygen.Generate(policygen.Input{
			Env: res.Env, Events: res.Events, Results: res.Results,
			FetchedAt: res.FetchedAt, Scenarios: res.Scenarios, Strict: *strict,
		}, policygen.Options{Policy: current, Fix: strings.Split(*fixWhat, ",")})
		if err != nil {
			return fmt.Errorf("generate a policy: %w", err)
		}
		if err := os.WriteFile(*genPolicy, plan.Output, 0o644); err != nil {
			return err
		}
		// Keep stdout machine-readable under --json.
		out := os.Stdout
		if *jsonOut {
			out = os.Stderr
		}
		fmt.Fprint(out, plan.Summary(*genPolicy))
	}
	if res.Failed() {
		os.Exit(1)
	}
	return nil
}

// jsonResult is the machine-readable form of a run, for CI.
type jsonResult struct {
	RunID       string        `json:"runId"`
	StartedAt   time.Time     `json:"startedAt"`
	Duration    string        `json:"duration"`
	Identity    string        `json:"identity"`
	LogSource   string        `json:"logSource"`
	Events      int           `json:"events"`
	Strict      bool          `json:"strict"`
	Counts      runner.Counts `json:"counts"`
	Failed      bool          `json:"failed"`
	IdleMBDay   float64       `json:"idleMBPerDay"`
	IdleGBYear  float64       `json:"idleGBPerYear"`
	BudgetGBYr  float64       `json:"budgetGBPerYear"`
	BudgetClean bool          `json:"budgetSampleClean"`
	Findings    []jsonFinding `json:"findings"`
}

type jsonFinding struct {
	Status      string   `json:"status"`
	Scenario    string   `json:"scenario"`
	Requirement string   `json:"requirement"`
	Description string   `json:"description"`
	Errors      []string `json:"errors,omitempty"`
	Gap         string   `json:"gap,omitempty"`
	Skipped     string   `json:"skipped,omitempty"`
}

func printJSON(res *runner.Result, opt runner.Options, started time.Time) error {
	out := jsonResult{
		RunID:       res.Env.RunID,
		StartedAt:   res.Env.Start.UTC(),
		Duration:    time.Since(started).Round(time.Second).String(),
		Identity:    res.Env.AdminUser,
		LogSource:   res.Env.Logs.Describe(),
		Events:      len(res.Events),
		Strict:      opt.Strict,
		Counts:      res.Counts(),
		Failed:      res.Failed(),
		BudgetGBYr:  res.Budget.GBPerYear,
		BudgetClean: res.Budget.Clean,
		IdleMBDay:   res.Budget.BytesPerDay(res.Budget.Background.Bytes) / 1e6,
		IdleGBYear:  res.Budget.IdleGBPerYear(),
	}
	for _, r := range res.Results {
		if r.Status() == "PASS" {
			continue
		}
		out.Findings = append(out.Findings, jsonFinding{
			Status:      r.Status(),
			Scenario:    r.Scenario,
			Requirement: r.Expect.Requirement,
			Description: r.Expect.Desc,
			Errors:      r.Errors,
			Gap:         r.Expect.Gap,
			Skipped:     r.Skipped,
		})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func scenariosCmd(args []string) error {
	fs := flag.NewFlagSet("scenarios", flag.ExitOnError)
	var common commonFlags
	common.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := common.load()
	if err != nil {
		return err
	}
	names := runner.ListScenarios(cfg)
	for _, n := range names {
		fmt.Println(n)
	}
	fmt.Printf("\n%d scenarios apply to this profile.\n", len(names))
	return nil
}

func configCmd(args []string) error {
	fs := flag.NewFlagSet("config", flag.ExitOnError)
	var common commonFlags
	common.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := common.load()
	if err != nil {
		return err
	}
	raw, err := cfg.Marshal()
	if err != nil {
		return err
	}
	fmt.Print(string(raw))
	return nil
}
