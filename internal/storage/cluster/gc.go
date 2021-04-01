package cluster

import (
	"fmt"
	"log"
	"time"
)

type GarbageCollector struct {
	cs               *ClusterStorage
	interval         time.Duration
	ticker           *time.Ticker
	done             chan struct{}
	collectorRunning bool
	isRunning        bool
	isStopped        bool
	quiet            bool
	debug            bool
}

func NewGC(cs *ClusterStorage, runInterval time.Duration, quiet, debug bool) *GarbageCollector {
	return &GarbageCollector{
		cs:       cs,
		interval: runInterval,
		done:     make(chan struct{}),
		quiet:    quiet,
		debug:    debug,
	}
}

func (gc *GarbageCollector) Collect() {
	gc.collectorRunning = true
	defer func() {
		gc.collectorRunning = false
	}()
	gc.logDebug("collector starting")
	err := gc.cs.deleteExpiredSecrets()
	if err != nil {
		gc.logDebug("error deleting expired secrets")
	}
	gc.logDebug("collector finished")
}

func (gc *GarbageCollector) Start() error {
	// Already running, do nothing
	if gc.isRunning {
		return nil
	}
	// After calling stop, a new instance must be constructed
	if !gc.isStopped {
		gc.ticker = time.NewTicker(gc.interval)
		go gc.run()
		gc.isRunning = true
		gc.log(fmt.Sprintf("starting garbage collector routine: interval: %d", gc.interval))
		return nil
	} else {
		return fmt.Errorf("calling start after stop is not supported, construct a new instance")
	}
}

func (gc *GarbageCollector) Stop() {
	// prevent panic panic when calling stop more than once
	if !gc.isStopped {
		gc.log("stopping garbage collector routine")
		gc.ticker.Stop()
		gc.done <- struct{}{}
		close(gc.done)
	}
}

func (gc *GarbageCollector) run() {
	for {
		select {
		case <-gc.done:
			gc.log("shutdown signal received, exiting loop")
			gc.isStopped = true
			gc.isRunning = false
			return
		case <-gc.ticker.C:
			gc.logDebug("ticker signal received")
			if !gc.collectorRunning {
				gc.Collect()
			}
		}
	}
}

func (gc *GarbageCollector) log(msg string) {
	if !gc.quiet {
		log.Printf("[GC: %p] %s", gc, msg)
	}
}

func (gc *GarbageCollector) logDebug(msg string) {
	if gc.debug {
		gc.log(msg)
	}
}
