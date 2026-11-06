package flow

import (
	"testing"

	"bininspect/internal/models"
)

func TestStackRelationsEx00(t *testing.T) {
	a := models.AssemblyAnalysis{
		Architecture: "Intel 80386",
		Instructions: []models.Instruction{
			{Mnemonic: "push", Operands: "ebp", Function: "main"},
			{Mnemonic: "mov", Operands: "ebp,esp", Function: "main"},
			{Mnemonic: "and", Operands: "esp,0xfffffff0", Function: "main"},
			{Mnemonic: "sub", Operands: "esp,0x60", Function: "main"},
			{Mnemonic: "mov", Operands: "DWORD PTR [esp+0x5c],0x0", Function: "main"},
			{Mnemonic: "lea", Operands: "eax,[esp+0x1c]", Function: "main"},
			{Mnemonic: "mov", Operands: "DWORD PTR [esp],eax", Function: "main"},
			{Mnemonic: "call", Target: "gets@plt", Address: "804840c", Function: "main", Kind: "call"},
			{Mnemonic: "mov", Operands: "eax,DWORD PTR [esp+0x5c]", Address: "8048411", Function: "main"},
			{Mnemonic: "test", Operands: "eax,eax", Function: "main"},
			{Mnemonic: "je", Operands: "8048427", Address: "8048417", Function: "main", Kind: "branch"},
		},
	}

	relations := Analyze(a, "ELF").Relations
	if len(relations) != 1 {
		t.Fatalf("expected 1 relation, got %d", len(relations))
	}

	if relations[0].Distance != 64 {
		t.Fatalf("expected 64 bytes, got %d", relations[0].Distance)
	}

	if !relations[0].InitializedZero {
		t.Fatal("expected zero-initialized stack location")
	}
}
