package models

var Scope struct {
	Target string
	Format string
}

type Engines struct {
	ELF     bool
	PE      bool
	MACH_O  bool
	Unknown bool
}

var ActiveEngines Engines
