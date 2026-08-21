package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"lite-clash-cli/internal/benchmark"
	configpkg "lite-clash-cli/internal/config"
	proxyserver "lite-clash-cli/internal/proxy"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

type options struct {
	configFile    string
	proxy         string
	proxyIndex    int
	proxyIndexSet bool
	listProxies   bool
	showVersion   bool
}

func main() {
	opts, err := parseOptions(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		os.Exit(2)
	}

	if opts.showVersion {
		fmt.Printf("lite-clash %s (standalone Trojan, built %s)\n", version, buildTime)
		return
	}

	if err := run(opts); err != nil {
		fmt.Fprintf(os.Stderr, "lite-clash: %v\n", err)
		os.Exit(1)
	}
}

func parseOptions(args []string) (options, error) {
	var opts options
	fs := flag.NewFlagSet("lite-clash", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&opts.configFile, "f", os.Getenv("LITE_CLASH_CONFIG_FILE"), "YAML configuration file (default ./config.yaml, use - for stdin)")
	fs.StringVar(&opts.proxy, "proxy", "", "use this Trojan proxy name")
	fs.Func("proxy-index", "use the Nth Trojan proxy (1-based)", func(value string) error {
		index, err := strconv.Atoi(value)
		if err != nil || index < 1 {
			return fmt.Errorf("proxy index must be a positive integer")
		}
		opts.proxyIndex = index
		opts.proxyIndexSet = true
		return nil
	})
	fs.BoolVar(&opts.listProxies, "list-proxies", false, "print configured Trojan proxy indexes and names, then exit")
	fs.BoolVar(&opts.showVersion, "v", false, "show version and exit")
	fs.BoolVar(&opts.showVersion, "version", false, "show version and exit")

	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintln(out, "Usage: lite-clash [options]")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "A small standalone Trojan proxy with YAML configuration.")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Options:")
		fmt.Fprintln(out, "  -f FILE")
		fmt.Fprintln(out, "        YAML configuration file (default ./config.yaml, use - for stdin)")
		fmt.Fprintln(out, "  -h, --help")
		fmt.Fprintln(out, "        show help and exit")
		fmt.Fprintln(out, "  -v")
		fmt.Fprintln(out, "        show version and exit")
		fmt.Fprintln(out, "  --list-proxies")
		fmt.Fprintln(out, "        print configured Trojan proxy indexes and names, then exit")
		fmt.Fprintln(out, "  --proxy NAME")
		fmt.Fprintln(out, "        use this Trojan proxy name")
		fmt.Fprintln(out, "  --proxy-index N")
		fmt.Fprintln(out, "        use the Nth Trojan proxy (1-based)")
		fmt.Fprintln(out, "  --version")
		fmt.Fprintln(out, "        show version and exit")
	}

	if err := validateFlagStyle(args); err != nil {
		fmt.Fprintf(fs.Output(), "lite-clash: %v\n", err)
		return options{}, err
	}
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if fs.NArg() != 0 {
		err := fmt.Errorf("unexpected argument %q", fs.Arg(0))
		fmt.Fprintf(fs.Output(), "lite-clash: %v\n", err)
		return options{}, err
	}
	if opts.proxy != "" && opts.proxyIndexSet {
		err := errors.New("--proxy and --proxy-index cannot be used together")
		fmt.Fprintf(fs.Output(), "lite-clash: %v\n", err)
		return options{}, err
	}
	return opts, nil
}

func validateFlagStyle(args []string) error {
	expectsValue := false
	for _, argument := range args {
		if expectsValue {
			expectsValue = false
			continue
		}
		if argument == "--" {
			break
		}
		if argument == "-" || !strings.HasPrefix(argument, "-") {
			continue
		}

		long := strings.HasPrefix(argument, "--")
		nameValue := strings.TrimPrefix(argument, "-")
		if long {
			nameValue = strings.TrimPrefix(nameValue, "-")
		}
		name, _, hasInlineValue := strings.Cut(nameValue, "=")
		if long && len(name) == 1 {
			return fmt.Errorf("single-letter option %q must be written as -%s", argument, name)
		}
		if !long && len(name) > 1 {
			return fmt.Errorf("multi-letter option %q must be written as --%s", argument, name)
		}
		if !hasInlineValue && (name == "f" || name == "proxy" || name == "proxy-index") {
			expectsValue = true
		}
	}
	return nil
}

func run(opts options) error {
	if err := configureConfigPath(&opts); err != nil {
		return err
	}

	raw, err := readConfig(opts)
	if err != nil {
		return err
	}
	cfg, err := parseRuntime(raw, opts)
	if err != nil {
		return err
	}

	if opts.listProxies {
		for index, proxy := range cfg.Proxies {
			fmt.Printf("%d\t%s\n", index+1, proxy.Name)
		}
		return nil
	}
	if opts.proxy == "" && !opts.proxyIndexSet {
		printBenchmarkResults(cfg)
		return nil
	}
	if err := cfg.ValidateListeners(); err != nil {
		return err
	}

	logger := log.New(os.Stderr, "", log.LstdFlags)
	application := proxyserver.New(cfg, logger)
	if err := application.Start(); err != nil {
		return err
	}
	defer application.Close()

	logger.Printf("lite-clash %s started with %s", version, configSource(opts))
	logger.Printf("using Trojan proxy %q", cfg.Selected.Name)

	terminate := make(chan os.Signal, 1)
	reload := make(chan os.Signal, 1)
	signal.Notify(terminate, syscall.SIGINT, syscall.SIGTERM)
	signal.Notify(reload, syscall.SIGHUP)
	defer signal.Stop(terminate)
	defer signal.Stop(reload)

	for {
		select {
		case <-terminate:
			logger.Printf("shutting down")
			return nil
		case <-reload:
			if opts.configFile == "-" {
				logger.Printf("SIGHUP ignored: configuration is not file-backed")
				continue
			}
			raw, err := readConfig(opts)
			if err != nil {
				logger.Printf("reload failed: %v", err)
				continue
			}
			next, err := parseRuntime(raw, opts)
			if err != nil {
				logger.Printf("reload failed: %v", err)
				continue
			}
			if err := application.Reload(next); err != nil {
				logger.Printf("reload failed: %v", err)
				continue
			}
			logger.Printf("configuration reloaded; using Trojan proxy %q", next.Selected.Name)
		}
	}
}

func parseRuntime(raw []byte, opts options) (*configpkg.Runtime, error) {
	cfg, err := configpkg.Parse(raw, opts.proxy)
	if err != nil {
		return nil, err
	}
	if opts.proxyIndexSet {
		if err := cfg.SelectProxyIndex(opts.proxyIndex); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

func printBenchmarkResults(cfg *configpkg.Runtime) {
	results := benchmark.All(context.Background(), cfg.Proxies, cfg.UnifiedDelay)
	for _, result := range results {
		if result.Err != nil {
			fmt.Printf("%d\t%s\tfail: %v\n", result.Index, result.Name, result.Err)
			continue
		}
		fmt.Printf("%d\t%s\t%d ms\n", result.Index, result.Name, result.DelayMS)
	}
}

func configureConfigPath(opts *options) error {
	if opts.configFile == "-" {
		return nil
	}
	if opts.configFile == "" {
		opts.configFile = "config.yaml"
	}
	absConfig, err := filepath.Abs(opts.configFile)
	if err != nil {
		return fmt.Errorf("resolve configuration file: %w", err)
	}
	opts.configFile = absConfig
	return nil
}

func readConfig(opts options) ([]byte, error) {
	var (
		data []byte
		err  error
	)
	if opts.configFile == "-" {
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read configuration from stdin: %w", err)
		}
	} else {
		data, err = os.ReadFile(opts.configFile)
		if err != nil {
			return nil, fmt.Errorf("read configuration %s: %w", opts.configFile, err)
		}
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, errors.New("configuration is empty")
	}
	return data, nil
}

func configSource(opts options) string {
	if opts.configFile == "-" {
		return "stdin"
	}
	return opts.configFile
}
