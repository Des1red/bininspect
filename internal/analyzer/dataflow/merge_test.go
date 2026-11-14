package dataflow

import "testing"

func TestMergeCallSites(t *testing.T) {
	calls := []CallTrace{
		{
			Function: "function_a",
			Section:  5,
			Address:  0x1000,
			Target:   "read",
			Arguments: []Argument{
				{
					Position: 1,
					Location: "rdi",
					Value: Value{
						Kind:   "constant",
						Number: 7,
					},
				},
				{
					Position: 2,
					Location: "rsi",
					Value: Value{
						Kind:        "stack-address",
						StackOffset: -32,
					},
				},
			},
		},
		{
			Function: "function_b",
			Section:  5,
			Address:  0x1000,
			Target:   "read",
			Arguments: []Argument{
				{
					Position: 1,
					Location: "rdi",
					Value: Value{
						Kind:   "constant",
						Number: 7,
					},
				},
				{
					Position: 2,
					Location: "rsi",
					Value: Value{
						Kind:        "stack-address",
						StackOffset: -64,
					},
				},
			},
		},
	}

	got := mergeCallSites(calls)

	if len(got) != 1 {
		t.Fatalf("expected one call site, got %d", len(got))
	}

	if got[0].Function != "ambiguous owner" {
		t.Fatalf("ownership was not marked ambiguous: %+v", got[0])
	}

	if got[0].Arguments[0].Value.Kind != "constant" ||
		got[0].Arguments[0].Value.Number != 7 {
		t.Fatal("common constant was lost")
	}

	if got[0].Arguments[1].Value.Kind != "" {
		t.Fatal("conflicting stack pointer was preserved")
	}
}

func TestMergePreservesSeparateSections(t *testing.T) {
	got := mergeCallSites([]CallTrace{
		{Section: 1, Address: 0x1000},
		{Section: 2, Address: 0x1000},
	})

	if len(got) != 2 {
		t.Fatalf("different ELF sections merged: %+v", got)
	}
}
