package osexit

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var exit sync.WaitGroup

var hooks []func(os.Signal)

func Before(cb func(os.Signal)) {
	hooks = append(hooks, cb)
}

func init() {
	go func() {

		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)
		s := <-c

		if len(hooks) == 0 {
			os.Exit(0)
			return
		}

		wg := sync.WaitGroup{}
		wg.Add(len(hooks))

		for i := 0; i < len(hooks); i++ {
			go func(i int) {
				hooks[i](s)
				time.Sleep(time.Second)
				wg.Done()
			}(i)
		}

		wg.Wait()

		time.Sleep(time.Second)
		os.Exit(0)
	}()

}
