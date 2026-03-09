package modules

import (
	"fmt"
	"strconv"
	"strings"
)

// ErrNotSupported is returned when a module doesn't support an operation (e.g. Check on an exploit-only module).
var ErrNotSupported = fmt.Errorf("operation not supported by this module")

// Module holds metadata about an exploit or check module.
type Module struct {
	Name         string
	Description  string
	Manufacturer string
	Category     string   // "SAFE" or "UNSAFE"
	Authors      []string
	Tags         []string
	Models       []string // Known compatible printer models
}

// Option describes a single configurable module option.
type Option struct {
	Name        string
	Value       string // current value (initialized to Default)
	Default     string
	Required    bool
	Description string
}

// CheckResult is returned by check modules after testing default credentials.
type CheckResult struct {
	Success  bool
	Target   string
	Port     int
	Username string
	Password string
	Details  string
}

// ExploitResult is returned by exploit modules after execution.
type ExploitResult struct {
	Success bool
	Target  string
	Port    int
	Details string
	Data    string // any captured data
}

// ExploitModule is the unified interface for interactive modules.
// A module may support Check, Exploit, or both.
type ExploitModule interface {
	Info() Module
	Options() []*Option
	SetOption(name, value string) error
	GetOption(name string) (*Option, error)
	Check() (*CheckResult, error)
	Exploit() (*ExploitResult, error)
	Validate() error
}

// BaseModule provides shared option storage and validation logic.
// Concrete modules embed this and implement Check/Exploit.
type BaseModule struct {
	Mod  Module
	Opts []*Option
}

func (b *BaseModule) Info() Module       { return b.Mod }
func (b *BaseModule) Options() []*Option { return b.Opts }

func (b *BaseModule) SetOption(name, value string) error {
	for _, o := range b.Opts {
		if strings.EqualFold(o.Name, name) {
			o.Value = value
			return nil
		}
	}
	return fmt.Errorf("unknown option %q", name)
}

func (b *BaseModule) GetOption(name string) (*Option, error) {
	for _, o := range b.Opts {
		if strings.EqualFold(o.Name, name) {
			return o, nil
		}
	}
	return nil, fmt.Errorf("unknown option %q", name)
}

func (b *BaseModule) Validate() error {
	for _, o := range b.Opts {
		if o.Required && o.Value == "" {
			return fmt.Errorf("required option %s is not set", o.Name)
		}
	}
	return nil
}

// Val returns the current value of an option by name, or empty string if not found.
func (b *BaseModule) Val(name string) string {
	o, err := b.GetOption(name)
	if err != nil {
		return ""
	}
	return o.Value
}

// IntVal returns the current value as an int, or fallback if parsing fails.
func (b *BaseModule) IntVal(name string, fallback int) int {
	s := b.Val(name)
	if s == "" {
		return fallback
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return n
}

// BoolVal returns true if the option value is "true" (case-insensitive).
func (b *BaseModule) BoolVal(name string) bool {
	return strings.EqualFold(b.Val(name), "true")
}

// InitDefaults sets each option's Value to its Default. Call this in the module constructor.
func (b *BaseModule) InitDefaults() {
	for _, o := range b.Opts {
		o.Value = o.Default
	}
}
