package modules

import (
	"strings"
	"sync"
)

// Registry holds all registered modules.
type Registry struct {
	mu        sync.RWMutex
	modules   map[string]ExploitModule
	factories map[string]func() ExploitModule
}

// NewRegistry creates an empty module registry.
func NewRegistry() *Registry {
	return &Registry{
		modules:   make(map[string]ExploitModule),
		factories: make(map[string]func() ExploitModule),
	}
}

// RegisterModule adds a unified ExploitModule to the registry.
func (r *Registry) RegisterModule(m ExploitModule) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.modules[strings.ToLower(m.Info().Name)] = m
}

// RegisterFactory stores a constructor function for creating fresh module instances.
func (r *Registry) RegisterFactory(name string, factory func() ExploitModule) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factories[strings.ToLower(name)] = factory
}

// NewModule creates a fresh instance of a module by name (case-insensitive).
// Returns nil, false if no factory is registered for the given name.
func (r *Registry) NewModule(name string) (ExploitModule, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	factory, ok := r.factories[strings.ToLower(name)]
	if !ok {
		return nil, false
	}
	return factory(), true
}

// GetModule retrieves a unified ExploitModule by name (case-insensitive).
func (r *Registry) GetModule(name string) (ExploitModule, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.modules[strings.ToLower(name)]
	return m, ok
}

// Search performs a case-insensitive search across all modules.
func (r *Registry) Search(term string) []Module {
	r.mu.RLock()
	defer r.mu.RUnlock()

	term = strings.ToLower(term)
	var matches []Module

	for _, m := range r.modules {
		info := m.Info()
		if moduleMatches(info, term) {
			matches = append(matches, info)
		}
	}

	return matches
}

// Names returns all module names (for tab completion).
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var names []string
	for name := range r.modules {
		names = append(names, name)
	}
	return names
}

func moduleMatches(m Module, term string) bool {
	if strings.Contains(strings.ToLower(m.Name), term) {
		return true
	}
	if strings.Contains(strings.ToLower(m.Description), term) {
		return true
	}
	if strings.Contains(strings.ToLower(m.Manufacturer), term) {
		return true
	}
	if strings.Contains(strings.ToLower(m.Category), term) {
		return true
	}
	for _, tag := range m.Tags {
		if strings.Contains(strings.ToLower(tag), term) {
			return true
		}
	}
	for _, model := range m.Models {
		if strings.Contains(strings.ToLower(model), term) {
			return true
		}
	}
	return false
}
