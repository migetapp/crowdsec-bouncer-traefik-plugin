package cache

import (
	"testing"
)

func TestRangeTreeInsertAndLookup(t *testing.T) {
	tree := NewRangeTree()

	tree.Insert("194.233.100.0/23", BannedValue, 3600)
	tree.Insert("10.0.0.0/8", BannedValue, 3600)
	tree.Insert("2001:db8::/32", BannedValue, 3600)

	tests := []struct {
		name     string
		ip       string
		wantVal  string
		wantHit  bool
	}{
		{"IP in /23 range start", "194.233.100.1", BannedValue, true},
		{"IP in /23 range end", "194.233.101.123", BannedValue, true},
		{"IP outside /23 range", "194.233.102.1", "", false},
		{"IP in /8 range", "10.5.3.7", BannedValue, true},
		{"IP outside /8 range", "11.0.0.1", "", false},
		{"IPv6 in range", "2001:db8::1", BannedValue, true},
		{"IPv6 outside range", "2001:db9::1", "", false},
		{"Invalid IP", "not-an-ip", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, hit := tree.Lookup(tt.ip)
			if hit != tt.wantHit {
				t.Errorf("Lookup(%s) hit = %v, want %v", tt.ip, hit, tt.wantHit)
			}
			if val != tt.wantVal {
				t.Errorf("Lookup(%s) val = %q, want %q", tt.ip, val, tt.wantVal)
			}
		})
	}
}

func TestRangeTreeDelete(t *testing.T) {
	tree := NewRangeTree()

	tree.Insert("192.168.0.0/16", BannedValue, 3600)

	val, hit := tree.Lookup("192.168.1.1")
	if !hit || val != BannedValue {
		t.Fatalf("expected hit before delete")
	}

	tree.Delete("192.168.0.0/16")

	_, hit = tree.Lookup("192.168.1.1")
	if hit {
		t.Fatalf("expected miss after delete")
	}
}

func TestRangeTreeExpiry(t *testing.T) {
	tree := NewRangeTree()

	// Insert with 0 second TTL — should already be expired
	tree.Insert("172.16.0.0/12", BannedValue, 0)

	_, hit := tree.Lookup("172.16.5.1")
	if hit {
		t.Fatalf("expected miss for expired entry")
	}
}

func TestRangeTreeMostSpecificMatch(t *testing.T) {
	tree := NewRangeTree()

	tree.Insert("10.0.0.0/8", BannedValue, 3600)
	tree.Insert("10.1.0.0/16", CaptchaValue, 3600)

	// Should match the more specific /16
	val, hit := tree.Lookup("10.1.2.3")
	if !hit {
		t.Fatalf("expected hit")
	}
	if val != CaptchaValue {
		t.Errorf("expected captcha for more specific match, got %q", val)
	}

	// Should match the /8
	val, hit = tree.Lookup("10.2.0.1")
	if !hit {
		t.Fatalf("expected hit")
	}
	if val != BannedValue {
		t.Errorf("expected ban for /8 match, got %q", val)
	}
}
