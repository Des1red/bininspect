package security

import (
	"debug/elf"
	"fmt"
	"strings"

	"bininspect/internal/binary"
)

// Check represents evidence recorded from the ELF file.
// It does not establish the runtime state of a process.
type Check struct {
	Status   string
	Evidence []string
	Note     string
}

type Result struct {
	NX      Check
	PIE     Check
	RELRO   Check
	Canary  Check
	Fortify Check
	ASLR    Check
	RWX     Check
}

func check(status, note string, evidence ...string) Check {
	return Check{
		Status:   status,
		Note:     note,
		Evidence: evidence,
	}
}

func Analyze(parsed *binary.ELFResult) Result {
	unknown := check("unknown", "Insufficient ELF evidence")

	out := Result{
		NX:    unknown,
		PIE:   unknown,
		RELRO: unknown,
		Canary: check(
			"not-observed",
			"No stack-canary-related symbol found; absence does not prove canaries are disabled",
		),
		Fortify: check(
			"not-observed",
			"No recognized fortified libc wrapper found; absence does not prove FORTIFY is disabled",
		),
		ASLR: unknown,
		RWX:  unknown,
	}

	if parsed == nil {
		return out
	}

	// Symbol-based hardening evidence.
	names := symbolNames(parsed)

	if has(names, "__stack_chk_fail") ||
		has(names, "__stack_chk_fail_local") {

		var evidence []string

		for _, name := range []string{
			"__stack_chk_fail",
			"__stack_chk_fail_local",
		} {
			if has(names, name) {
				evidence = append(
					evidence, "ELF symbol: "+name,
				)
			}
		}

		out.Canary = check(
			"detected",
			"Stack-canary support is indicated; coverage of individual functions is not proven",
			evidence...,
		)
	} else if has(names, "__stack_chk_guard") {
		out.Canary = check(
			"possible",
			"Canary guard symbol exists, but no stack-fail reference was found",
			"ELF symbol: __stack_chk_guard",
		)
	}

	var fortified []string

	for _, name := range []string{
		"__memcpy_chk",
		"__memmove_chk",
		"__memset_chk",
		"__strcpy_chk",
		"__strncpy_chk",
		"__strcat_chk",
		"__strncat_chk",
		"__stpcpy_chk",
		"__sprintf_chk",
		"__vsprintf_chk",
		"__snprintf_chk",
		"__vsnprintf_chk",
		"__printf_chk",
		"__fprintf_chk",
		"__fgets_chk",
		"__read_chk",
		"__recv_chk",
		"__realpath_chk",
		"__open_2",
		"__open64_2",
	} {
		if has(names, name) {
			fortified = append(
				fortified, "ELF symbol: "+name,
			)
		}
	}

	if len(fortified) > 0 {
		out.Fortify = check(
			"detected",
			"Fortified wrapper symbols are present; this does not establish full call-site coverage",
			fortified...,
		)
	}

	// Relocatable objects do not have final linked protections.
	if parsed.Header.Type == elf.ET_REL {
		notLinked := check(
			"not-applicable",
			"Relocatable object: final linked hardening cannot be determined",
		)

		out.NX = notLinked
		out.PIE = notLinked
		out.RELRO = notLinked
		out.ASLR = notLinked
		out.RWX = notLinked

		return out
	}

	if parsed.Header.Type != elf.ET_EXEC &&
		parsed.Header.Type != elf.ET_DYN {
		return out
	}

	var stackCount, loadCount, rwxCount int
	var stackExec, hasRELRO, hasInterp bool

	for _, p := range parsed.Programs {
		switch p.Type {
		case elf.PT_GNU_STACK:
			stackCount++

			if p.Flags&elf.PF_X != 0 {
				stackExec = true
			}

		case elf.PT_GNU_RELRO:
			if p.Memsz != 0 {
				hasRELRO = true
			}

		case elf.PT_INTERP:
			hasInterp = true

		case elf.PT_LOAD:
			loadCount++

			if p.Flags&elf.PF_W != 0 &&
				p.Flags&elf.PF_X != 0 {
				rwxCount++
			}
		}
	}

	// NX / executable stack.
	switch {
	case stackCount > 1:
		out.NX = check(
			"unknown",
			"Multiple PT_GNU_STACK headers; stack executability is ambiguous",
			fmt.Sprintf(
				"PT_GNU_STACK entries: %d", stackCount,
			),
		)

	case stackCount == 1 && stackExec:
		out.NX = check(
			"disabled",
			"ELF requests an executable process stack",
			"PT_GNU_STACK: PF_X set",
		)

	case stackCount == 1:
		out.NX = check(
			"enabled",
			"ELF does not request an executable stack; runtime policy may differ",
			"PT_GNU_STACK: PF_X clear",
		)
	}

	// Writable and executable load segments.
	if loadCount > 0 {
		if rwxCount > 0 {
			out.RWX = check(
				"present",
				"One or more loadable segments are both writable and executable",
				fmt.Sprintf(
					"RWX PT_LOAD segments: %d", rwxCount,
				),
			)
		} else {
			out.RWX = check(
				"not-observed",
				"No RWX PT_LOAD segment in the ELF program headers",
			)
		}
	}

	// Parse dynamic linker flags.
	var bindNow, pieFlag bool

	for _, entry := range parsed.Dynamic.Entries {
		switch entry.Tag {
		case elf.DT_BIND_NOW:
			bindNow = true

		case elf.DT_FLAGS:
			if entry.Value&uint64(elf.DF_BIND_NOW) != 0 {
				bindNow = true
			}

		case elf.DT_FLAGS_1:
			if entry.Value&uint64(elf.DF_1_NOW) != 0 {
				bindNow = true
			}

			if entry.Value&uint64(elf.DF_1_PIE) != 0 {
				pieFlag = true
			}
		}
	}

	// PIE and ASLR compatibility.
	switch parsed.Header.Type {
	case elf.ET_EXEC:
		out.PIE = check(
			"disabled",
			"Executable has a fixed ELF image type",
			"e_type: ET_EXEC",
		)

		out.ASLR = check(
			"limited",
			"Non-PIE executable text is not position-independent; other mappings may still be randomized",
			"e_type: ET_EXEC",
		)

	case elf.ET_DYN:
		out.ASLR = check(
			"compatible",
			"ET_DYN is relocatable; actual randomization depends on the loader and system",
			"e_type: ET_DYN",
		)

		switch {
		case pieFlag:
			out.PIE = check(
				"enabled",
				"DF_1_PIE explicitly marks the object as PIE",
				"DT_FLAGS_1: DF_1_PIE",
			)

		case hasInterp:
			out.PIE = check(
				"likely",
				"ET_DYN plus PT_INTERP is consistent with PIE but lacks DF_1_PIE",
				"e_type: ET_DYN",
				"PT_INTERP present",
			)

		default:
			out.PIE = check(
				"not-applicable",
				"ET_DYN without PIE flag or interpreter is treated as a shared object",
				"e_type: ET_DYN",
			)
		}
	}

	// RELRO protection.
	if hasRELRO {
		switch {
		case bindNow:
			out.RELRO = check(
				"full",
				"RELRO and immediate symbol binding are requested",
				"PT_GNU_RELRO present",
				"DT_BIND_NOW / DF_BIND_NOW / DF_1_NOW",
			)

		case !parsed.Dynamic.Present:
			out.RELRO = check(
				"enabled",
				"RELRO is requested and no PT_DYNAMIC lazy binding is present",
				"PT_GNU_RELRO present",
				"PT_DYNAMIC absent",
			)

		default:
			out.RELRO = check(
				"partial",
				"RELRO is requested but lazy binding may remain",
				"PT_GNU_RELRO present",
				"BIND_NOW not observed",
			)
		}
	} else if len(parsed.Programs) > 0 {
		out.RELRO = check(
			"disabled",
			"No nonempty PT_GNU_RELRO segment found",
			"PT_GNU_RELRO absent",
		)
	}

	return out
}

func symbolNames(parsed *binary.ELFResult) map[string]struct{} {
	names := make(map[string]struct{})

	add := func(symbols []binary.ELFSymbol) {
		for _, symbol := range symbols {
			name := strings.SplitN(
				symbol.Name, "@", 2,
			)[0]

			if name != "" {
				names[name] = struct{}{}
			}
		}
	}

	add(parsed.Metadata.Symbols)
	add(parsed.DynamicMetadata.Symbols)

	return names
}

func has(names map[string]struct{}, name string) bool {
	_, ok := names[name]
	return ok
}
