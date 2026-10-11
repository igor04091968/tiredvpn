package server

import (
	"errors"
	"testing"
	"time"
)

func TestNewGOSTHandshakeSemaphoreDefaultAndOverride(t *testing.T) {
	sem, limit, err := newGOSTHandshakeSemaphore(&Config{})
	if err != nil {
		t.Fatal(err)
	}
	if limit != defaultMaxConcurrentGOSTHandshakes || cap(sem) != defaultMaxConcurrentGOSTHandshakes {
		t.Fatalf("default GOST handshake limit=%d/cap=%d, want %d", limit, cap(sem), defaultMaxConcurrentGOSTHandshakes)
	}

	sem, limit, err = newGOSTHandshakeSemaphore(&Config{GOSTMaxHandshakes: 19})
	if err != nil {
		t.Fatal(err)
	}
	if limit != 19 || cap(sem) != 19 {
		t.Fatalf("configured GOST handshake limit=%d/cap=%d, want 19", limit, cap(sem))
	}
	if _, _, err := newGOSTHandshakeSemaphore(&Config{GOSTMaxHandshakes: -1}); err == nil {
		t.Fatal("negative GOST handshake limit was accepted")
	}
}

func TestGOSTHandshakeSemaphoreBoundsWorkAndReleasesAfterHandshake(t *testing.T) {
	sem := make(chan struct{}, 1)
	firstStarted := make(chan struct{})
	firstRelease := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- performGOSTHandshake(sem, func() error {
			close(firstStarted)
			<-firstRelease
			return nil
		})
	}()
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first handshake did not enter")
	}

	secondAttempted := make(chan struct{})
	secondStarted := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		close(secondAttempted)
		secondDone <- performGOSTHandshake(sem, func() error {
			close(secondStarted)
			return nil
		})
	}()
	<-secondAttempted
	select {
	case <-secondStarted:
		t.Fatal("second handshake entered while the only slot was occupied")
	case <-time.After(25 * time.Millisecond):
	}
	if got := len(sem); got != 1 {
		t.Fatalf("occupied GOST handshake slots=%d, want 1", got)
	}

	close(firstRelease)
	if err := <-firstDone; err != nil {
		t.Fatalf("first handshake: %v", err)
	}
	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		t.Fatal("second handshake did not start after first released its slot")
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second handshake: %v", err)
	}
	if got := len(sem); got != 0 {
		t.Fatalf("slots after successful handshakes=%d, want 0", got)
	}

	wantErr := errors.New("simulated TLS failure")
	if err := performGOSTHandshake(sem, func() error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("failed handshake error=%v, want %v", err, wantErr)
	}
	if got := len(sem); got != 0 {
		t.Fatalf("slots after failed handshake=%d, want 0", got)
	}
}
