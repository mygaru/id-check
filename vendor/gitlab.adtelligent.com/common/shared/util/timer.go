package util

import (
	"sync"
	"time"
)

var timerPool sync.Pool

func AcquireTimer(timeout time.Duration) *time.Timer {
	tv := timerPool.Get()
	if tv == nil {
		return time.NewTimer(timeout)
	}

	t := tv.(*time.Timer)
	t.Reset(timeout)
	return t
}

func ReleaseTimer(t *time.Timer) {
	t.Stop()

	// Collect possibly added time from the channel
	// if timer has been stopped and nobody collected its' value.
	select {
	case <-t.C:
	default:
	}

	timerPool.Put(t)
}

// SleepTill sleeps until the next rounded interval.
//
// Example: if called at 18:20 with interval=time.Hour
// it will sleep for 40*time.Minute.
func SleepTill(interval time.Duration) {
	now := time.Now()
	d := now.Truncate(interval).Add(interval).Sub(now)

	// Solving the problem of starting a repeated cycle at boundary values
	if d <= time.Millisecond {
		time.Sleep(time.Millisecond)

		now = time.Now()
		d = now.Truncate(interval).Add(interval).Sub(now)
	}
	time.Sleep(d)
}
