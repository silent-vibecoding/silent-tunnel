// Package state is the live statistics store both daemon roles keep on
// disk so `silent status` can report from another session.
package state

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// State holds the runtime counters. hub and node embed a pointer to it and
// bump the atomic fields directly.
type State struct {
	Role string

	Sessions   atomic.Int64  // healthy tunnel connections
	Streams    atomic.Int64  // in-flight forwarded connections
	Total      atomic.Uint64 // streams ever opened
	In         atomic.Uint64 // bytes received from the tunnel
	Out        atomic.Uint64 // bytes sent into the tunnel
	Reconnects atomic.Uint64 // successful (re)connects

	peer      atomic.Value
	started   time.Time
	fmu       sync.Mutex
	forwarded []int
}

func New(role string) *State {
	return &State{Role: role, started: time.Now()}
}

// SetPeer records the address of the most recent tunnel peer.
func (s *State) SetPeer(addr string) { s.peer.Store(addr) }

// Peer returns the last seen peer address ("" when none).
func (s *State) Peer() string { v, _ := s.peer.Load().(string); return v }

// SetForwarded records the currently forwarded port list.
func (s *State) SetForwarded(ports []int) {
	s.fmu.Lock()
	s.forwarded = append([]int(nil), ports...)
	s.fmu.Unlock()
}

// Forwarded returns a copy of the currently forwarded port list.
func (s *State) Forwarded() []int {
	s.fmu.Lock()
	defer s.fmu.Unlock()
	return append([]int(nil), s.forwarded...)
}

// disk is the JSON shape persisted to the status file.
type disk struct {
	Role         string `json:"role"`
	StartedAt    string `json:"started_at"`
	Sessions     int64  `json:"sessions"`
	StreamsOpen  int64  `json:"streams_open"`
	TotalStreams uint64 `json:"total_streams"`
	BytesIn      uint64 `json:"bytes_in"`
	BytesOut     uint64 `json:"bytes_out"`
	Reconnects   uint64 `json:"reconnects"`
	Forwarded    []int  `json:"forwarded"`
	LastPeer     string `json:"last_peer"`
	UpdatedAt    string `json:"updated_at"`
}

func (s *State) snapshot() disk {
	return disk{
		Role:         s.Role,
		StartedAt:    s.started.Format(time.RFC3339),
		Sessions:     s.Sessions.Load(),
		StreamsOpen:  s.Streams.Load(),
		TotalStreams: s.Total.Load(),
		BytesIn:      s.In.Load(),
		BytesOut:     s.Out.Load(),
		Reconnects:   s.Reconnects.Load(),
		Forwarded:    s.Forwarded(),
		LastPeer:     s.Peer(),
		UpdatedAt:    time.Now().Format(time.RFC3339),
	}
}

// WriteLoop persists the state immediately and then every interval until
// stop closes (a final write happens on shutdown too).
func (s *State) WriteLoop(path string, interval time.Duration, stop <-chan struct{}) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Printf("status dir: %v", err)
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	s.persist(path)
	for {
		select {
		case <-stop:
			s.persist(path)
			return
		case <-t.C:
			s.persist(path)
		}
	}
}

func (s *State) persist(path string) {
	b, err := json.MarshalIndent(s.snapshot(), "", "  ")
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		log.Printf("status write: %v", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("status rename: %v", err)
	}
}
