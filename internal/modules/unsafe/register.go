package unsafe

import "papercut/internal/modules"

// factories collects module constructors added by init() in each module file.
var factories []func() modules.ExploitModule

// register adds a module factory. Called from init() in each module file.
func register(f func() modules.ExploitModule) {
	factories = append(factories, f)
}

// RegisterAll registers all UNSAFE modules with the given registry.
// Module factories are auto-collected via init() — no manual editing needed here.
func RegisterAll(r *modules.Registry) {
	for _, f := range factories {
		m := f()
		name := m.Info().Name
		r.RegisterModule(m)
		r.RegisterFactory(name, f)
	}
}
