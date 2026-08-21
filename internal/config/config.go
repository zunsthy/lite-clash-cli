package config

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"lite-clash-cli/internal/trojan"

	"gopkg.in/yaml.v3"
)

type rawConfig struct {
	Port           int             `yaml:"port"`
	SocksPort      int             `yaml:"socks-port"`
	RedirPort      int             `yaml:"redir-port"`
	MixedPort      int             `yaml:"mixed-port"`
	AllowLAN       bool            `yaml:"allow-lan"`
	BindAddress    string          `yaml:"bind-address"`
	Authentication []string        `yaml:"authentication"`
	UnifiedDelay   bool            `yaml:"unified-delay"`
	IPv6           bool            `yaml:"ipv6"`
	Proxies        []trojan.Config `yaml:"proxies"`
}

type Credentials map[string]string

type Runtime struct {
	Port         int
	SocksPort    int
	RedirPort    int
	MixedPort    int
	BindAddress  string
	IPv6         bool
	Users        Credentials
	UnifiedDelay bool
	Proxies      []trojan.Config
	Selected     trojan.Config
	listenerKey  string
}

func Parse(data []byte, requestedProxy string) (*Runtime, error) {
	var raw rawConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}

	users, err := parseCredentials(raw.Authentication)
	if err != nil {
		return nil, err
	}
	if err := validatePorts(raw.Port, raw.SocksPort, raw.MixedPort, raw.RedirPort); err != nil {
		return nil, err
	}

	if len(raw.Proxies) == 0 {
		return nil, errors.New("configuration must contain at least one inline Trojan proxy")
	}
	seen := make(map[string]struct{}, len(raw.Proxies))
	selectedIndex := -1
	for i := range raw.Proxies {
		proxy := &raw.Proxies[i]
		if err := validateTrojanProxy(proxy, i); err != nil {
			return nil, err
		}
		if _, exists := seen[proxy.Name]; exists {
			return nil, fmt.Errorf("duplicate proxy name %q", proxy.Name)
		}
		seen[proxy.Name] = struct{}{}
		if requestedProxy != "" && proxy.Name == requestedProxy {
			selectedIndex = i
		}
	}
	if requestedProxy == "" {
		selectedIndex = 0
	} else if selectedIndex == -1 {
		return nil, fmt.Errorf("proxy %q is not present in the Trojan proxy list", requestedProxy)
	}

	bindAddress := raw.BindAddress
	if bindAddress == "" || bindAddress == "*" {
		if raw.AllowLAN {
			bindAddress = "0.0.0.0"
		} else {
			bindAddress = "127.0.0.1"
		}
	}
	cfg := &Runtime{
		Port:         raw.Port,
		SocksPort:    raw.SocksPort,
		RedirPort:    raw.RedirPort,
		MixedPort:    raw.MixedPort,
		BindAddress:  bindAddress,
		IPv6:         raw.IPv6,
		Users:        users,
		UnifiedDelay: raw.UnifiedDelay,
		Proxies:      raw.Proxies,
		Selected:     raw.Proxies[selectedIndex],
	}
	cfg.listenerKey = makeListenerKey(cfg)
	return cfg, nil
}

func validateTrojanProxy(proxy *trojan.Config, index int) error {
	if proxy.Name == "" {
		return fmt.Errorf("proxies[%d] has no valid name", index)
	}
	if proxy.Type != "trojan" {
		return fmt.Errorf("proxies[%d] %q uses unsupported proxy type %q; only \"trojan\" is supported", index, proxy.Name, proxy.Type)
	}
	if proxy.Server == "" {
		return fmt.Errorf("Trojan proxy %q has no server", proxy.Name)
	}
	if proxy.Port < 1 || proxy.Port > 65535 {
		return fmt.Errorf("Trojan proxy %q has invalid port %d", proxy.Name, proxy.Port)
	}
	if proxy.Password == "" {
		return fmt.Errorf("Trojan proxy %q has no password", proxy.Name)
	}
	if proxy.Network != "" && proxy.Network != "tcp" {
		return fmt.Errorf("Trojan proxy %q uses unsupported network %q; only plain TCP Trojan is supported", proxy.Name, proxy.Network)
	}
	if len(proxy.Extra) != 0 {
		keys := make([]string, 0, len(proxy.Extra))
		for key := range proxy.Extra {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		return fmt.Errorf("Trojan proxy %q uses unsupported option(s): %s", proxy.Name, strings.Join(keys, ", "))
	}
	if proxy.SNI == "" {
		proxy.SNI = proxy.Server
	}
	if proxy.ALPN == nil {
		proxy.ALPN = append([]string(nil), trojan.DefaultALPN...)
	}
	return nil
}

func parseCredentials(values []string) (Credentials, error) {
	result := make(Credentials, len(values))
	for _, value := range values {
		user, password, ok := strings.Cut(value, ":")
		if !ok || user == "" {
			return nil, fmt.Errorf("invalid authentication entry %q; expected username:password", value)
		}
		result[user] = password
	}
	return result, nil
}

func validatePorts(ports ...int) error {
	seen := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		if port == 0 {
			continue
		}
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid listening port %d", port)
		}
		if _, exists := seen[port]; exists {
			return fmt.Errorf("listening port %d is configured more than once", port)
		}
		seen[port] = struct{}{}
	}
	return nil
}

func (cfg *Runtime) SelectProxyIndex(index int) error {
	if index < 1 || index > len(cfg.Proxies) {
		return fmt.Errorf("proxy index %d is out of range; expected 1..%d", index, len(cfg.Proxies))
	}
	cfg.Selected = cfg.Proxies[index-1]
	return nil
}

func (cfg *Runtime) ValidateListeners() error {
	if cfg.Port == 0 && cfg.SocksPort == 0 && cfg.MixedPort == 0 && cfg.RedirPort == 0 {
		return errors.New("no local proxy port is configured")
	}
	return nil
}

func makeListenerKey(cfg *Runtime) string {
	users := make([]string, 0, len(cfg.Users))
	for user, password := range cfg.Users {
		users = append(users, user+":"+password)
	}
	sort.Strings(users)
	return strings.Join([]string{
		cfg.BindAddress,
		strconv.Itoa(cfg.Port),
		strconv.Itoa(cfg.SocksPort),
		strconv.Itoa(cfg.MixedPort),
		strconv.Itoa(cfg.RedirPort),
		strings.Join(users, "\x00"),
	}, "|")
}

func (cfg *Runtime) ListenAddress(port int) string {
	return net.JoinHostPort(cfg.BindAddress, strconv.Itoa(port))
}

func (cfg *Runtime) ListenerKey() string {
	return cfg.listenerKey
}
