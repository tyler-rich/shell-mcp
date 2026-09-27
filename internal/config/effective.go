package config

// Effective is the printable form of a Config: secrets are replaced by their
// length (token) or public-key fingerprint (SSH keys).
type Effective struct {
	Profile              string            `json:"profile"`
	DisableTools         []string          `json:"disable_tools"`
	Transport            string            `json:"transport"`
	Bind                 string            `json:"bind"`
	Port                 int               `json:"port"`
	Path                 string            `json:"path"`
	AuthMode             string            `json:"auth_mode"`
	TokenLength          int               `json:"token_length"`
	AllowUnauthenticated bool              `json:"allow_unauthenticated"`
	AllowedHosts         []string          `json:"allowed_hosts"`
	AllowedOrigins       []string          `json:"allowed_origins"`
	TrustProxy           bool              `json:"trust_proxy"`
	RateLimitPerMin      int               `json:"rate_limit_per_min"`
	Targets              []EffectiveTarget `json:"targets"`
	DefaultTarget        string            `json:"default_target"`
	SSHConnectTimeoutS   int               `json:"ssh_connect_timeout_s"`
	SSHMaxSessions       int               `json:"ssh_max_sessions"`
	DefaultTimeoutS      int               `json:"default_timeout_s"`
	MaxTimeoutS          int               `json:"max_timeout_s"`
	MaxOutputBytes       int               `json:"max_output_bytes"`
	ApprovalTiers        []string          `json:"approval_tiers"`
	ApprovalFallback     string            `json:"approval_fallback"`
	ApprovalTTLS         int               `json:"approval_ttl_s"`
	RedactPatterns       int               `json:"redact_patterns"`
	LogLevel             string            `json:"log_level"`
	LogFormat            string            `json:"log_format"`
	Warnings             []string          `json:"warnings"`
}

// EffectiveTarget is the printable form of a Target.
type EffectiveTarget struct {
	Name           string   `json:"name"`
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	User           string   `json:"user"`
	HostKeys       []string `json:"host_keys"`
	KeyFingerprint string   `json:"key_fingerprint"`
}

// Effective returns the configuration with every secret masked.
func (c *Config) Effective() Effective {
	e := Effective{
		Profile:              c.Profile,
		DisableTools:         nonNil(c.DisableTools),
		Transport:            c.Transport,
		Bind:                 c.Bind,
		Port:                 c.Port,
		Path:                 c.Path,
		AuthMode:             c.AuthMode,
		TokenLength:          c.Token.Len(),
		AllowUnauthenticated: c.AllowUnauthenticated,
		AllowedHosts:         nonNil(c.AllowedHosts),
		AllowedOrigins:       nonNil(c.AllowedOrigins),
		TrustProxy:           c.TrustProxy,
		RateLimitPerMin:      c.RateLimitPerMin,
		Targets:              make([]EffectiveTarget, 0, len(c.Targets)),
		DefaultTarget:        c.DefaultTarget,
		SSHConnectTimeoutS:   int(c.SSHConnectTimeout.Seconds()),
		SSHMaxSessions:       c.SSHMaxSessions,
		DefaultTimeoutS:      int(c.DefaultTimeout.Seconds()),
		MaxTimeoutS:          int(c.MaxTimeout.Seconds()),
		MaxOutputBytes:       c.MaxOutputBytes,
		ApprovalTiers:        nonNil(c.ApprovalTiers),
		ApprovalFallback:     c.ApprovalFallback,
		ApprovalTTLS:         int(c.ApprovalTTL.Seconds()),
		RedactPatterns:       len(c.RedactPatterns),
		LogLevel:             c.LogLevel,
		LogFormat:            c.LogFormat,
		Warnings:             nonNil(c.Warnings),
	}
	for _, t := range c.Targets {
		e.Targets = append(e.Targets, EffectiveTarget{
			Name: t.Name, Host: t.Host, Port: t.Port, User: t.User,
			HostKeys: nonNil(t.HostKeys), KeyFingerprint: t.Key.Fingerprint(),
		})
	}
	return e
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
