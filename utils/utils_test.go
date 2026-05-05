package utils

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRunWhileFalse_Instant(t *testing.T) {
	f := func() bool { return true }
	assert.True(t, RunWhileFalse(f, time.Minute, time.Minute))
}

func TestRunWhileFalse_1SecTimeoutFalse(t *testing.T) {
	f := func() bool { return false }

	begin := time.Now()
	result := RunWhileFalse(f, time.Second, time.Second)
	diff := time.Since(begin)

	assert.False(t, result)
	assert.True(t, diff.Seconds() > 0 && diff.Seconds() < 2)
}

func TestRunWhileFalse_NoTimeout(t *testing.T) {
	f := func() bool { return false }

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	go func() {
		RunWhileFalse(f, 0*time.Second, time.Second)
		cancel()
	}()

	<-ctx.Done()
	assert.Equal(t, context.DeadlineExceeded, ctx.Err())
}

func TestRunWhileFalse_1SecTimeoutTrue(t *testing.T) {
	var ret atomic.Bool
	f := ret.Load
	time.AfterFunc(1*time.Second, func() { ret.Store(true) })

	assert.True(t, RunWhileFalse(f, 5*time.Second, time.Second))
}
