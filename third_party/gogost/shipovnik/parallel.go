package shipovnik

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
)

var autoWorkerBudget = make(chan struct{}, runtime.GOMAXPROCS(0))

func resolveWorkers(options *Options, rounds, automaticLimit int) (workers int, automatic bool, err error) {
	requested := 0
	if options != nil {
		requested = options.Workers
	}
	if requested < 0 {
		return 0, false, ErrInvalidOptions
	}
	if requested == 0 {
		requested = automaticLimit
		automatic = true
	}
	if requested < 1 {
		requested = 1
	}
	if requested > rounds {
		requested = rounds
	}
	return requested, automatic, nil
}

func automaticSignWorkers() int {
	// The entropy producer is one of the leased participants. Let a lone Sign
	// operation use the full process budget; concurrent automatic operations
	// still share the bounded token pool and therefore cannot oversubscribe it.
	return max(1, runtime.GOMAXPROCS(0))
}

func automaticVerifyWorkers() int {
	processors := runtime.GOMAXPROCS(0)
	return max(1, (5*processors+5)/6)
}

func acquireAutoWorkers(ctx context.Context, requested int) (int, error) {
	select {
	case autoWorkerBudget <- struct{}{}:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	acquired := 1
	for acquired < requested {
		select {
		case autoWorkerBudget <- struct{}{}:
			acquired++
		default:
			return acquired, nil
		}
	}
	return acquired, nil
}

func releaseAutoWorkers(workers int) {
	for range workers {
		<-autoWorkerBudget
	}
}

type workerLease struct {
	workers   int
	automatic bool
}

func acquireWorkerLease(ctx context.Context, workers int, automatic bool) (workerLease, error) {
	if !automatic {
		return workerLease{workers: workers}, nil
	}
	acquired, err := acquireAutoWorkers(ctx, workers)
	if err != nil {
		return workerLease{}, err
	}
	return workerLease{workers: acquired, automatic: true}, nil
}

func (lease workerLease) release() {
	if lease.automatic {
		releaseAutoWorkers(lease.workers)
	}
}

// parallelTwoPhase runs first for every ordered round, waits for all workers at
// a barrier, and only then starts second. The same goroutine team and worker
// indices are retained across both phases. Callers may put expensive rounds
// first to minimize load imbalance at the tail of the cryptographic phase.
func parallelTwoPhase(
	ctx context.Context,
	order []uint16,
	workers int,
	first, second func(worker, round int) error,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	count := len(order)
	if workers <= 1 {
		for _, encodedRound := range order {
			round := int(encodedRound)
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := first(0, round); err != nil {
				return err
			}
		}
		for _, encodedRound := range order {
			round := int(encodedRound)
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := second(0, round); err != nil {
				return err
			}
		}
		return ctx.Err()
	}

	child, cancel := context.WithCancel(ctx)
	defer cancel()
	var firstNext, secondNext atomic.Int64
	var validationDone sync.WaitGroup
	validationDone.Add(workers)
	var once sync.Once
	var operationErr error
	fail := func(err error) {
		once.Do(func() {
			operationErr = err
			cancel()
		})
	}
	work := func(worker int) {
		for child.Err() == nil {
			position := int(firstNext.Add(1) - 1)
			if position >= count {
				break
			}
			round := int(order[position])
			if err := first(worker, round); err != nil {
				fail(err)
				break
			}
		}
		validationDone.Done()
		validationDone.Wait()
		if child.Err() != nil {
			return
		}
		for child.Err() == nil {
			position := int(secondNext.Add(1) - 1)
			if position >= count {
				return
			}
			round := int(order[position])
			if err := second(worker, round); err != nil {
				fail(err)
				return
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(workers - 1)
	for worker := 1; worker < workers; worker++ {
		go func(worker int) {
			defer wg.Done()
			work(worker)
		}(worker)
	}
	work(0)
	wg.Wait()
	if operationErr != nil {
		return operationErr
	}
	return ctx.Err()
}
