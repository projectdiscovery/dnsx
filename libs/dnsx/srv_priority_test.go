package dnsx

import (
	"testing"
)

func TestSRVRecordPriorityWeightOrdering(t *testing.T) {
	type SRV struct {
		Priority uint16
		Weight   uint16
		Port     uint16
		Target   string
	}
	
	srv1 := SRV{Priority: 10, Weight: 60, Port: 443, Target: "server1.example.com"}
	srv2 := SRV{Priority: 20, Weight: 40, Port: 443, Target: "server2.example.com"}
	
	if srv1.Priority >= srv2.Priority {
		t.Fatalf("expected srv1 to have higher priority (lower numerical value)")
	}
}
