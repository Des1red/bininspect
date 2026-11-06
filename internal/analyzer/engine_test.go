package analyzer

import (
	"strings"
	"testing"

	"bininspect/internal/models"
)

// Analyzer tests use global models, so they must run sequentially.
func isolateEngine(t *testing.T) {
	t.Helper()

	oldScope := models.Scope
	oldKnowledge := models.Knowledge
	oldResults := models.Results

	t.Cleanup(func() {
		models.Scope = oldScope
		models.Knowledge = oldKnowledge
		models.Results = oldResults
	})

	reset(&models.Scope)
	reset(&models.Knowledge)
	reset(&models.Results)
}

func reset[T any](dst *T) {
	var zero T
	*dst = zero
}

func loadELF(assembly, imported string) {
	models.Scope.Format = "ELF"

	models.Knowledge.File =
		"ELF 32-bit LSB executable, Intel 80386"

	models.Knowledge.ELF = `
  Class:                             ELF32
  Data:                              2's complement, little endian
  Type:                              EXEC (Executable file)
  Machine:                           Intel 80386
  Entry point address:               0x8048340
`

	models.Knowledge.Programs =
		"  GNU_STACK 0x000000 0x00000000 0x00000000 " +
			"0x000000 0x000000 RWE 0x10\n"

	models.Knowledge.Symbols =
		"  1: 00000000 0 FUNC GLOBAL DEFAULT UND " +
			imported + "\n"

	models.Knowledge.Dynamic =
		"0x00000001 (NEEDED) Shared library: [libc.so.6]\n"

	models.Knowledge.Assembly = assembly
}

// Synthetic objdump-format fixtures based on the
// instruction sequences examined in ex00 and ex01.

const ex00Assembly = `
080483f4 <main>:
 80483f4: 55                    push ebp
 80483f5: 89 e5                 mov ebp,esp
 80483f7: 83 e4 f0              and esp,0xfffffff0
 80483fa: 83 ec 60              sub esp,0x60
 80483fd: c7 44 24 5c 00        mov DWORD PTR [esp+0x5c],0x0
 8048405: 8d 44 24 1c           lea eax,[esp+0x1c]
 8048409: 89 04 24              mov DWORD PTR [esp],eax
 804840c: e8 fb fe ff ff        call 804830c <gets@plt>
 8048411: 8b 44 24 5c           mov eax,DWORD PTR [esp+0x5c]
 8048415: 85 c0                 test eax,eax
 8048417: 74 0e                 je 8048427 <main+0x33>
`

const ex01Assembly = `
08048464 <main>:
 8048464: 55                    push ebp
 8048465: 89 e5                 mov ebp,esp
 8048467: 83 e4 f0              and esp,0xfffffff0
 804846a: 83 ec 60              sub esp,0x60
 804846d: c7 44 24 5c 00        mov DWORD PTR [esp+0x5c],0x0
 8048475: 8b 45 0c              mov eax,DWORD PTR [ebp+0xc]
 8048478: 83 c0 04              add eax,0x4
 804847b: 8b 00                 mov eax,DWORD PTR [eax]
 804847d: 89 44 24 04           mov DWORD PTR [esp+0x4],eax
 8048497: 8d 44 24 1c           lea eax,[esp+0x1c]
 804849b: 89 04 24              mov DWORD PTR [esp],eax
 80484a2: e8 c1 fe ff ff        call 8048368 <strcpy@plt>
 80484a7: 8b 44 24 5c           mov eax,DWORD PTR [esp+0x5c]
 80484ab: 3d 64 63 62 61        cmp eax,0x61626364
 80484b0: 75 0e                 jne 80484c0 <main+0x5c>
`

func findingCount(id string) (int, models.Finding) {
	count := 0
	var found models.Finding

	for _, finding := range models.Results.Findings {
		if finding.ID == id {
			count++
			found = finding
		}
	}

	return count, found
}

func TestEngineEx00(t *testing.T) {
	isolateEngine(t)
	loadELF(ex00Assembly, "gets")

	Engine()
	got := models.Results

	// Identity
	if got.Identity.Format != "ELF" ||
		got.Identity.Architecture != "Intel 80386" {

		t.Fatalf("identity: %+v", got.Identity)
	}

	// Function discovery
	if len(got.FunctionDefinitions) != 1 ||
		got.FunctionDefinitions[0].Name != "main" {

		t.Fatalf(
			"function definitions: %+v",
			got.FunctionDefinitions,
		)
	}

	// Call resolution
	if got.Assembly.Calls != 1 ||
		len(got.Functions) != 1 ||
		got.Functions[0].Name != "gets" {

		t.Fatalf(
			"calls: parsed=%d, resolved=%+v",
			got.Assembly.Calls,
			got.Functions,
		)
	}

	// Argument tracking
	if len(got.Assembly.CallFlows) != 1 ||
		len(got.Assembly.CallFlows[0].Arguments) != 1 {

		t.Fatalf(
			"call flow: %+v",
			got.Assembly.CallFlows,
		)
	}

	// Stack analysis
	if len(got.Assembly.StackRelations) != 1 {
		t.Fatalf(
			"stack relations: %+v",
			got.Assembly.StackRelations,
		)
	}

	relation := got.Assembly.StackRelations[0]

	if relation.Distance != 64 ||
		!relation.InitializedZero ||
		relation.API != "gets" ||
		relation.ComparedValue != "0x0" {

		t.Fatalf(
			"unexpected stack relation: %+v",
			relation,
		)
	}

	// Security protections
	if got.Security.NX.Status != "disabled" ||
		got.Security.PIE.Status != "disabled" {

		t.Fatalf("security: %+v", got.Security)
	}

	// Collection coverage
	if !got.Sources["assembly"].Available ||
		!got.Sources["elf"].Available {

		t.Fatalf("coverage: %+v", got.Sources)
	}

	// Findings and deduplication
	count, api := findingCount("API-gets")

	if count != 1 ||
		!strings.Contains(api.Evidence, "64 bytes") ||
		!strings.Contains(
			api.Evidence,
			"Import/symbol reference",
		) {

		t.Fatalf(
			"consolidated API finding: count=%d, finding=%+v",
			count,
			api,
		)
	}

	if len(got.Findings) != 3 {
		t.Fatalf(
			"expected API, NX and PIE findings, got %+v",
			got.Findings,
		)
	}
}

func TestEngineEx01(t *testing.T) {
	isolateEngine(t)
	loadELF(ex01Assembly, "strcpy")

	Engine()
	got := models.Results

	// strcpy requires destination and source arguments.
	if len(got.Assembly.CallFlows) != 1 ||
		len(got.Assembly.CallFlows[0].Arguments) != 2 {

		t.Fatalf(
			"strcpy arguments: %+v",
			got.Assembly.CallFlows,
		)
	}

	destination := got.Assembly.CallFlows[0].Arguments[0]

	if destination.StackReference != "[esp+0x1c]" {
		t.Fatalf(
			"destination argument: %+v",
			destination,
		)
	}

	// Detect the relationship to the checked stack variable.
	if len(got.Assembly.StackRelations) != 1 {
		t.Fatalf(
			"stack relations: %+v",
			got.Assembly.StackRelations,
		)
	}

	relation := got.Assembly.StackRelations[0]

	if relation.Distance != 64 ||
		relation.ComparedValue != "0x61626364" ||
		relation.API != "strcpy" {

		t.Fatalf(
			"unexpected relation: %+v",
			relation,
		)
	}

	// The comparison should be attached to one API finding.
	count, api := findingCount("API-strcpy")

	if count != 1 ||
		!strings.Contains(
			api.Evidence,
			"0x61626364",
		) {

		t.Fatalf(
			"strcpy finding: count=%d, finding=%+v",
			count,
			api,
		)
	}
}

func TestEngineResetsResults(t *testing.T) {
	isolateEngine(t)

	// First analysis: ELF with an unsafe API.
	loadELF(ex00Assembly, "gets")
	Engine()

	if len(models.Results.Findings) == 0 {
		t.Fatal("first run unexpectedly empty")
	}

	// Second analysis: unrelated unknown binary.
	reset(&models.Knowledge)
	models.Scope.Format = "Unknown"
	models.Knowledge.File = "data"

	Engine()

	got := models.Results

	if got.Identity.Format != "Unknown" ||
		len(got.Findings) != 0 ||
		len(got.Functions) != 0 ||
		len(got.Assembly.StackRelations) != 0 ||
		len(got.Assembly.CallFlows) != 0 {

		t.Fatalf(
			"results leaked from previous run: %+v",
			got,
		)
	}
}
