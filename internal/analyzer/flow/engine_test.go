package flow

import (
	"testing"

	"bininspect/internal/models"
)

func ins(fn, addr, op, args, target, kind string) models.Instruction {
	return models.Instruction{
		Function: fn,
		Address:  addr,
		Mnemonic: op,
		Operands: args,
		Target:   target,
		Kind:     kind,
	}
}

func TestEx00(t *testing.T) {
	a := models.AssemblyAnalysis{
		Architecture: "Intel 80386",
		Instructions: []models.Instruction{
			ins("main", "1", "push", "ebp", "", ""),
			ins("main", "2", "mov", "ebp,esp", "", ""),
			ins("main", "3", "and", "esp,0xfffffff0", "", ""),
			ins("main", "4", "sub", "esp,0x60", "", ""),
			ins("main", "5", "mov", "[esp+0x5c],0x0", "", ""),
			ins("main", "6", "lea", "eax,[esp+0x1c]", "", ""),
			ins("main", "7", "mov", "[esp],eax", "", ""),
			ins("main", "804840c", "call", "", "gets@plt", "call"),
			ins("main", "8048411", "mov", "eax,[esp+0x5c]", "", ""),
			ins("main", "8048415", "test", "eax,eax", "", ""),
			ins("main", "8048417", "je", "8048427", "", "branch"),
		},
	}

	r := Analyze(a, "ELF")

	if len(r.Relations) != 1 {
		t.Fatalf("expected 1 relation, got %d", len(r.Relations))
	}

	got := r.Relations[0]

	if got.Distance != 64 ||
		!got.InitializedZero ||
		got.ComparedValue != "0x0" ||
		got.ReadSite != "8048411" {
		t.Fatalf("unexpected relation: %+v", got)
	}
}

func TestEx01(t *testing.T) {
	a := models.AssemblyAnalysis{
		Architecture: "Intel 80386",
		Instructions: []models.Instruction{
			ins("main", "1", "push", "ebp", "", ""),
			ins("main", "2", "mov", "ebp,esp", "", ""),
			ins("main", "3", "and", "esp,0xfffffff0", "", ""),
			ins("main", "4", "sub", "esp,0x60", "", ""),
			ins("main", "5", "mov", "[esp+0x5c],0x0", "", ""),
			ins("main", "6", "mov", "eax,[ebp+0xc]", "", ""),
			ins("main", "7", "add", "eax,0x4", "", ""),
			ins("main", "8", "mov", "eax,[eax]", "", ""),
			ins("main", "9", "mov", "[esp+0x4],eax", "", ""),
			ins("main", "10", "lea", "eax,[esp+0x1c]", "", ""),
			ins("main", "11", "mov", "[esp],eax", "", ""),
			ins("main", "80484a2", "call", "", "strcpy@plt", "call"),
			ins("main", "80484a7", "mov", "eax,[esp+0x5c]", "", ""),
			ins("main", "80484ab", "cmp", "eax,0x61626364", "", ""),
			ins("main", "80484b0", "jne", "80484c0", "", "branch"),
		},
	}

	r := Analyze(a, "ELF")

	if len(r.Relations) != 1 {
		t.Fatalf("expected 1 relation, got %d", len(r.Relations))
	}

	got := r.Relations[0]

	if got.Distance != 64 ||
		got.ComparedValue != "0x61626364" ||
		got.ReadSite != "80484a7" ||
		got.SourceReference == "unknown" {
		t.Fatalf("unexpected relation: %+v", got)
	}
}

func TestBoundedCopy(t *testing.T) {
	a := models.AssemblyAnalysis{
		Architecture: "Intel 80386",
		Instructions: []models.Instruction{
			ins("main", "1", "sub", "esp,0x60", "", ""),
			ins("main", "2", "lea", "eax,[esp+0x1c]", "", ""),
			ins("main", "3", "mov", "[esp],eax", "", ""),
			ins("main", "4", "mov", "[esp+0x8],0x40", "", ""),
			ins("main", "5", "call", "", "memcpy@plt", "call"),
			ins("main", "6", "mov", "eax,[esp+0x5c]", "", ""),
			ins("main", "7", "test", "eax,eax", "", ""),
			ins("main", "8", "jne", "target", "", "branch"),
		},
	}

	r := Analyze(a, "ELF")

	if len(r.Relations) != 0 {
		t.Fatalf("unexpected relation: %+v", r.Relations)
	}
}

func TestAMD64(t *testing.T) {
	a := models.AssemblyAnalysis{
		Architecture: "Advanced Micro Devices X86-64",
		Instructions: []models.Instruction{
			ins("main", "1", "sub", "rsp,0x80", "", ""),
			ins("main", "2", "lea", "rdi,[rsp+0x20]", "", ""),
			ins("main", "3", "mov", "rsi,rax", "", ""),
			ins("main", "4", "call", "", "strcpy@plt", "call"),
			ins("main", "5", "mov", "eax,[rsp+0x60]", "", ""),
			ins("main", "6", "test", "eax,eax", "", ""),
			ins("main", "7", "jne", "target", "", "branch"),
		},
	}

	r := Analyze(a, "ELF")

	if len(r.Relations) != 1 || r.Relations[0].Distance != 64 {
		t.Fatalf("unexpected result: %+v", r)
	}
}

func TestWindowsX64(t *testing.T) {
	a := models.AssemblyAnalysis{
		Architecture: "i386:x86-64",
		Instructions: []models.Instruction{
			ins("main", "1", "sub", "rsp,0x80", "", ""),
			ins("main", "2", "lea", "rcx,[rsp+0x20]", "", ""),
			ins("main", "3", "mov", "rdx,rax", "", ""),
			ins("main", "4", "call", "", "strcpy", "call"),
			ins("main", "5", "cmp", "[rsp+0x60],0x41424344", "", ""),
			ins("main", "6", "je", "target", "", "branch"),
		},
	}

	r := Analyze(a, "PE")

	if len(r.Relations) != 1 ||
		r.Relations[0].Distance != 64 ||
		r.Relations[0].ComparedValue != "0x41424344" {
		t.Fatalf("unexpected result: %+v", r)
	}
}

func TestPushArguments(t *testing.T) {
	a := models.AssemblyAnalysis{
		Architecture: "Intel 80386",
		Instructions: []models.Instruction{
			ins("main", "1", "sub", "esp,0x60", "", ""),
			ins("main", "2", "lea", "eax,[esp+0x20]", "", ""),
			ins("main", "3", "push", "ecx", "", ""),
			ins("main", "4", "push", "eax", "", ""),
			ins("main", "5", "call", "", "strcpy", "call"),
			ins("main", "6", "add", "esp,0x8", "", ""),
			ins("main", "7", "cmp", "[esp+0x60],0", "", ""),
			ins("main", "8", "jne", "target", "", "branch"),
		},
	}

	r := Analyze(a, "ELF")

	if len(r.Relations) != 1 || r.Relations[0].Distance != 64 {
		t.Fatalf("unexpected result: %+v", r)
	}
}
