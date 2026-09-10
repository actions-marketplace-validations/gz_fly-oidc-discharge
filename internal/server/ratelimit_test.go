package server

import (
	"testing"
	"time"
)

// The bucket allows a burst, denies past it, and refills with elapsed time.
func TestRateLimiter(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	limiter := newRateLimiter(5, 3, func() time.Time { return now })

	for i := range 3 {
		if !limiter.allow() {
			t.Fatalf("burst request %d denied", i+1)
		}
	}
	if limiter.allow() {
		t.Error("a fourth request passed with an empty bucket")
	}

	// One fifth of a second at 5/s is exactly one token.
	now = now.Add(200 * time.Millisecond)
	if !limiter.allow() {
		t.Error("a refilled token was not granted")
	}
	if limiter.allow() {
		t.Error("more than the refilled token was granted")
	}

	// Idling does not accumulate beyond the burst.
	now = now.Add(time.Hour)
	granted := 0
	for limiter.allow() {
		granted++
		if granted > 10 {
			break
		}
	}
	if granted != 3 {
		t.Errorf("after a long idle the bucket granted %d, want the burst of 3", granted)
	}
}
