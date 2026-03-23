// Package cache implements utility routines for manipulating cache.
// rangetree.go provides a radix tree for efficient CIDR range lookups.
// This enables stream mode to match incoming IPs against Range-scoped decisions.
package cache

import (
	"net"
	"sync"
	"time"
)

// rangeEntry stores the remediation value and expiry for a CIDR decision.
type rangeEntry struct {
	value     string
	expiresAt time.Time
}

// radixNode is a binary trie node for IP prefix matching.
type radixNode struct {
	entry *rangeEntry
	left  *radixNode // bit 0
	right *radixNode // bit 1
}

// RangeTree is a thread-safe radix tree for CIDR range lookups.
type RangeTree struct {
	mu   sync.RWMutex
	root *radixNode
}

// NewRangeTree creates a new empty RangeTree.
func NewRangeTree() *RangeTree {
	return &RangeTree{root: &radixNode{}}
}

// Insert adds a CIDR range with a remediation value and TTL.
func (t *RangeTree) Insert(cidr, value string, durationSeconds int64) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}
	prefixLen, _ := ipNet.Mask.Size()
	ipBytes := ipNet.IP

	// Normalize IPv4 to 4 bytes
	if v4 := ipBytes.To4(); v4 != nil {
		ipBytes = v4
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	node := t.root
	for i := 0; i < prefixLen; i++ {
		byteIndex := i / 8
		bitIndex := 7 - (i % 8)
		bit := (ipBytes[byteIndex] >> uint(bitIndex)) & 1

		if bit == 0 {
			if node.left == nil {
				node.left = &radixNode{}
			}
			node = node.left
		} else {
			if node.right == nil {
				node.right = &radixNode{}
			}
			node = node.right
		}
	}

	node.entry = &rangeEntry{
		value:     value,
		expiresAt: time.Now().Add(time.Duration(durationSeconds) * time.Second),
	}
}

// Delete removes a CIDR range from the tree.
func (t *RangeTree) Delete(cidr string) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}
	prefixLen, _ := ipNet.Mask.Size()
	ipBytes := ipNet.IP

	if v4 := ipBytes.To4(); v4 != nil {
		ipBytes = v4
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	node := t.root
	for i := 0; i < prefixLen; i++ {
		byteIndex := i / 8
		bitIndex := 7 - (i % 8)
		bit := (ipBytes[byteIndex] >> uint(bitIndex)) & 1

		if bit == 0 {
			if node.left == nil {
				return
			}
			node = node.left
		} else {
			if node.right == nil {
				return
			}
			node = node.right
		}
	}
	node.entry = nil
}

// Lookup checks if an IP address falls within any stored CIDR range.
// Returns the remediation value and true if found, empty string and false otherwise.
func (t *RangeTree) Lookup(ipStr string) (string, bool) {
	ipAddr := net.ParseIP(ipStr)
	if ipAddr == nil {
		return "", false
	}

	ipBytes := ipAddr
	if v4 := ipAddr.To4(); v4 != nil {
		ipBytes = v4
	}

	totalBits := len(ipBytes) * 8

	t.mu.RLock()
	defer t.mu.RUnlock()

	node := t.root
	var lastMatch *rangeEntry
	now := time.Now()

	for i := 0; i < totalBits; i++ {
		byteIndex := i / 8
		bitIndex := 7 - (i % 8)
		bit := (ipBytes[byteIndex] >> uint(bitIndex)) & 1

		if bit == 0 {
			node = node.left
		} else {
			node = node.right
		}

		if node == nil {
			break
		}

		if node.entry != nil && now.Before(node.entry.expiresAt) {
			lastMatch = node.entry
		}
	}

	if lastMatch != nil {
		return lastMatch.value, true
	}
	return "", false
}
