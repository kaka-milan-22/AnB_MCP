package alice

import "testing"

// splitRedacted is the pure half of the combined-redact optimization: anb_exec
// concatenates stdout + sentinel + stderr, redacts the whole thing in ONE
// `alice redact` spawn (down from two), then splits the result back into the
// two streams here. If the sentinel did not survive redaction we must report
// ok=false so the caller can fall back to redacting each stream separately —
// never silently mis-attribute one stream's bytes to the other.
func TestSplitRedacted(t *testing.T) {
	tests := []struct {
		name       string
		combined   string
		wantStdout string
		wantStderr string
		wantOK     bool
	}{
		{
			name:       "splits at the sentinel",
			combined:   "stdout-text" + redactStreamSplit + "stderr-text",
			wantStdout: "stdout-text",
			wantStderr: "stderr-text",
			wantOK:     true,
		},
		{
			name:       "both streams empty",
			combined:   "" + redactStreamSplit + "",
			wantStdout: "",
			wantStderr: "",
			wantOK:     true,
		},
		{
			name:       "empty stderr keeps stdout intact",
			combined:   "only-stdout" + redactStreamSplit,
			wantStdout: "only-stdout",
			wantStderr: "",
			wantOK:     true,
		},
		{
			name:       "missing sentinel reports not-ok for fallback",
			combined:   "sentinel was eaten by redaction",
			wantStdout: "",
			wantStderr: "",
			wantOK:     false,
		},
		{
			name:       "splits on the first sentinel only",
			combined:   "a" + redactStreamSplit + "b" + redactStreamSplit + "c",
			wantStdout: "a",
			wantStderr: "b" + redactStreamSplit + "c",
			wantOK:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStdout, gotStderr, gotOK := splitRedacted(tt.combined)
			if gotOK != tt.wantOK {
				t.Fatalf("ok = %v, want %v", gotOK, tt.wantOK)
			}
			if gotStdout != tt.wantStdout {
				t.Errorf("stdout = %q, want %q", gotStdout, tt.wantStdout)
			}
			if gotStderr != tt.wantStderr {
				t.Errorf("stderr = %q, want %q", gotStderr, tt.wantStderr)
			}
		})
	}
}
