package main

import (
	"math"
	"testing"
)

func TestParseVMStatSummary(t *testing.T) {
	raw := `
4096 bytes per page
1,234 pages free
`

	summary := parseVMStatSummary(raw)
	if !summary.HasPageSize {
		t.Fatalf("expected page size to be detected")
	}
	if !summary.HasFreePages {
		t.Fatalf("expected free pages to be detected")
	}
	if summary.PageSize != 4096 {
		t.Fatalf("unexpected page size: got %d want %d", summary.PageSize, 4096)
	}
	if summary.FreePages != 1234 {
		t.Fatalf("unexpected free pages: got %d want %d", summary.FreePages, 1234)
	}
}

func TestParseIostatDeduplicatesDevices(t *testing.T) {
	raw := `
disk xfer read write
sd0 1 2 3
sd1 4 5 6
sd0: 7 8 9
`

	rows := parseIostat(raw)
	if len(rows) != 2 {
		t.Fatalf("unexpected row count: got %d want %d", len(rows), 2)
	}

	row := findIODeviceRow(rows, "sd0")
	if row == nil {
		t.Fatalf("expected sd0 row to exist")
	}
	if got := row.Metrics["xfer"]; got != "7" {
		t.Fatalf("unexpected xfer value: got %q want %q", got, "7")
	}
	if got := row.Metrics["read"]; got != "8" {
		t.Fatalf("unexpected read value: got %q want %q", got, "8")
	}
	if got := row.Metrics["write"]; got != "9" {
		t.Fatalf("unexpected write value: got %q want %q", got, "9")
	}
}

func TestParseCPUTicks(t *testing.T) {
	ticks, ok := parseCPUTicks("123 45 67 8 910")
	if !ok {
		t.Fatalf("expected cpu ticks to parse")
	}
	if ticks.User != 123 || ticks.Nice != 45 || ticks.System != 67 || ticks.Intr != 8 || ticks.Idle != 910 {
		t.Fatalf("unexpected cpu ticks: %+v", ticks)
	}

	ticks, ok = parseCPUTicks("kern.cp_time = { 500, 40, 70, 10, 900 }")
	if !ok {
		t.Fatalf("expected cpu ticks to parse with labels/braces")
	}
	if ticks.User != 500 || ticks.Nice != 40 || ticks.System != 70 || ticks.Intr != 10 || ticks.Idle != 900 {
		t.Fatalf("unexpected cpu ticks from labeled input: %+v", ticks)
	}
}

func TestParseCPUTicksRejectsInvalidInput(t *testing.T) {
	if _, ok := parseCPUTicks("12 34"); ok {
		t.Fatalf("expected parse failure for short input")
	}
	if _, ok := parseCPUTicks("12 xx 34 56 78"); ok {
		t.Fatalf("expected parse failure for non-numeric input")
	}
}

func TestSystemTrendStoreKeepsRecentSeries(t *testing.T) {
	store := newSystemTrendStore(3)

	store.pushMemoryPercent(10)
	store.pushMemoryPercent(20)
	store.pushMemoryPercent(30)
	store.pushMemoryPercent(40)

	store.pushCPUTicks(cpuTickStat{User: 100, Nice: 0, System: 50, Intr: 0, Idle: 850})
	store.pushCPUTicks(cpuTickStat{User: 200, Nice: 0, System: 100, Intr: 0, Idle: 900})
	store.pushCPUTicks(cpuTickStat{User: 220, Nice: 0, System: 140, Intr: 0, Idle: 940})

	snap := store.snapshot()
	if snap == nil {
		t.Fatalf("expected trend snapshot")
	}

	if len(snap.MemoryUsedPct) != 3 {
		t.Fatalf("unexpected memory series length: got %d want 3", len(snap.MemoryUsedPct))
	}
	if snap.MemoryUsedPct[0] != 20 || snap.MemoryUsedPct[1] != 30 || snap.MemoryUsedPct[2] != 40 {
		t.Fatalf("unexpected memory series: %+v", snap.MemoryUsedPct)
	}

	if len(snap.CPUUserPercent) != 2 {
		t.Fatalf("unexpected cpu user series length: got %d want 2", len(snap.CPUUserPercent))
	}
	if len(snap.CPUSystemPercent) != 2 {
		t.Fatalf("unexpected cpu system series length: got %d want 2", len(snap.CPUSystemPercent))
	}

	if math.Abs(snap.CPUUserPercent[0]-50.0) > 0.001 || math.Abs(snap.CPUSystemPercent[0]-25.0) > 0.001 {
		t.Fatalf("unexpected first cpu sample: user=%f system=%f", snap.CPUUserPercent[0], snap.CPUSystemPercent[0])
	}
	if math.Abs(snap.CPUUserPercent[1]-20.0) > 0.001 || math.Abs(snap.CPUSystemPercent[1]-40.0) > 0.001 {
		t.Fatalf("unexpected second cpu sample: user=%f system=%f", snap.CPUUserPercent[1], snap.CPUSystemPercent[1])
	}
}

func TestResolveTLSMode(t *testing.T) {
	mode, err := resolveTLSMode(false, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mode != tlsModeOff {
		t.Fatalf("unexpected mode: got %q want %q", mode, tlsModeOff)
	}

	mode, err = resolveTLSMode(true, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mode != tlsModeSelfSigned {
		t.Fatalf("unexpected mode: got %q want %q", mode, tlsModeSelfSigned)
	}

	mode, err = resolveTLSMode(true, "/tmp/cert.pem", "/tmp/key.pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mode != tlsModeManual {
		t.Fatalf("unexpected mode: got %q want %q", mode, tlsModeManual)
	}
}

func TestResolveTLSModeRejectsInvalidCombinations(t *testing.T) {
	if _, err := resolveTLSMode(false, "/tmp/cert.pem", ""); err == nil {
		t.Fatalf("expected error when tls is disabled but cert/key are provided")
	}
	if _, err := resolveTLSMode(true, "/tmp/cert.pem", ""); err == nil {
		t.Fatalf("expected error when only cert is provided")
	}
	if _, err := resolveTLSMode(true, "", "/tmp/key.pem"); err == nil {
		t.Fatalf("expected error when only key is provided")
	}
}

func findIODeviceRow(rows []ioDeviceStat, name string) *ioDeviceStat {
	target := normalizeIODeviceName(name)
	for i := range rows {
		if normalizeIODeviceName(rows[i].Device) == target {
			return &rows[i]
		}
	}
	return nil
}
