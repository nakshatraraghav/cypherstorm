package app

// Phase identifies a UI-neutral operation stage.
type Phase string

const (
	PhaseValidating    Phase = "validating"
	PhaseArchiving     Phase = "archiving"
	PhaseCompressing   Phase = "compressing"
	PhaseEncrypting    Phase = "encrypting"
	PhaseDecrypting    Phase = "decrypting"
	PhaseDecompressing Phase = "decompressing"
	PhaseExtracting    Phase = "extracting"
	PhaseHashing       Phase = "hashing"
	PhaseBenchmarking  Phase = "benchmarking"
	PhasePublishing    Phase = "publishing"
	PhaseComplete      Phase = "complete"
)

type Event struct {
	Phase   Phase
	Current int64
	Total   int64
	Detail  string
}

// EventSink is invoked synchronously. Adapters must return promptly; a TUI
// should coalesce events into a bounded channel rather than block I/O.
type EventSink func(Event)

func emit(sink EventSink, event Event) {
	if sink != nil {
		sink(event)
	}
}
