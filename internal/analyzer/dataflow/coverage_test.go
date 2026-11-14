package dataflow

import (
	"testing"

	"bininspect/internal/analyzer/cfg"
)

func TestMissingCallSites(t *testing.T) {
	graphs := []cfg.Graph{
		{
			Section: 5,
			Calls: []cfg.CallSite{
				{
					Address:   0x1000,
					Target:    0xe60,
					HasTarget: true,
				},
				{
					Address:   0x1010,
					Target:    0xe60,
					HasTarget: true,
				},
				{
					Address:  0x1020,
					Symbol:   "external_api",
					Indirect: true,
				},
			},
		},
		{
			Section: 6,
			Calls: []cfg.CallSite{
				{Address: 0x1000},
			},
		},
	}

	traces := []CallTrace{
		{
			Section: 5,
			Address: 0x1000,
		},
	}

	names := map[uint64]string{
		0xe60: "strerror_r",
	}

	got := missingCallSites(graphs, traces, names)

	if len(got) != 3 {
		t.Fatalf("expected 3 untraced calls, got %+v", got)
	}

	if got[0].Address != 0x1010 ||
		got[0].Target != "strerror_r" {
		t.Fatalf("PLT name lost: %+v", got[0])
	}

	if got[1].Address != 0x1020 ||
		got[1].Target != "external_api" ||
		!got[1].Indirect {
		t.Fatalf("relocation evidence lost: %+v", got[1])
	}

	if got[2].Section != 6 ||
		got[2].Address != 0x1000 {
		t.Fatalf("section identity lost: %+v", got[2])
	}
}

func TestNoMissingCallSites(t *testing.T) {
	graphs := []cfg.Graph{{
		Section: 1,
		Calls: []cfg.CallSite{
			{Address: 0x2000},
		},
	}}

	traces := []CallTrace{
		{Section: 1, Address: 0x2000},
	}

	got := missingCallSites(
		graphs,
		traces,
		nil,
	)

	if len(got) != 0 {
		t.Fatalf("traced call marked missing: %+v", got)
	}
}
