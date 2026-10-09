package modes

import (
	"runtime"

	"gitverse.ru/uzer_007/gogost/v3/internal/errx"
)

const (
	parallelBlockMinBytes  = 256 * 1024
	parallelStreamMinBytes = 512 * 1024
	parallelChunkBytes     = 256 * 1024
)

type parallelJob struct {
	start int
	end   int
	op    parallelOp
	stop  bool
}

type parallelOp uint8

const (
	parallelOpEncryptBlocks parallelOp = iota
	parallelOpDecryptBlocks
	parallelOpCBCDecrypt
	parallelOpCFBDecrypt
	parallelOpCTR
	parallelOpCTRACPKM
)

type parallelContext struct {
	block     blockCipher
	bulk      blockBulkCipher
	fast      ctrCounterBlock
	dst       []byte
	src       []byte
	iv        []byte
	blockSize int
	acpkm     *CTRACPKM
}

type parallelScratch struct {
	counter [16]byte
	gamma   [16]byte
}

type parallelExecutor struct {
	workers int
	jobs    chan parallelJob
	done    chan struct{}
	stopped chan struct{}
	ctx     parallelContext
}

type parallelState struct {
	fixedWorkers int
	exec         *parallelExecutor
}

func autoWorkers(n, blockSize int) int {
	return autoWorkersMin(n, blockSize, parallelBlockMinBytes)
}

func autoWorkersMin(n, blockSize, minBytes int) int {
	if n < minBytes || blockSize <= 0 {
		return 1
	}
	chunkBlocks := parallelChunkBytes / blockSize
	if chunkBlocks < 1 {
		chunkBlocks = 1
	}
	blocks := n / blockSize
	if blocks < 2 {
		return 1
	}
	workers := (blocks + chunkBlocks - 1) / chunkBlocks
	maxWorkers := runtime.GOMAXPROCS(0)
	if workers > maxWorkers {
		workers = maxWorkers
	}
	if workers < 2 {
		return 1
	}
	return workers
}

func (p *parallelState) setWorkers(workers int) error {
	if workers <= 1 {
		return errx.Wrap(ErrInvalidInput, "workers должно быть больше 1")
	}
	p.fixedWorkers = workers
	if p.exec != nil && p.exec.workers != workers {
		p.close()
	}
	p.ensure(workers)
	return nil
}

func (p *parallelState) resetWorkers() {
	p.fixedWorkers = 0
	p.close()
}

func (p *parallelState) close() {
	if p.exec != nil {
		p.exec.close()
		p.exec = nil
	}
}

func (p *parallelState) workers(n, blockSize, requested, minBytes int) int {
	if requested > 0 {
		return capWorkers(n, blockSize, requested)
	}
	if p.fixedWorkers > 0 {
		return capWorkers(n, blockSize, p.fixedWorkers)
	}
	return autoWorkersMin(n, blockSize, minBytes)
}

func (p *parallelState) runOp(n, blockSize, workers int, op parallelOp, ctx parallelContext) {
	if n == 0 {
		return
	}
	workers = capWorkers(n, blockSize, workers)
	if workers <= 1 {
		var scratch parallelScratch
		runParallelOp(op, &ctx, 0, n, &scratch)
		return
	}
	p.ensure(workers)
	p.exec.runContext(n/blockSize, blockSize, workers, op, ctx)
}

func (p *parallelState) runUnitsOp(units, workers int, op parallelOp, ctx parallelContext) {
	if units == 0 {
		return
	}
	if workers <= 1 || units < 2 {
		var scratch parallelScratch
		runParallelOp(op, &ctx, 0, units, &scratch)
		return
	}
	if workers > units {
		workers = units
	}
	p.ensure(workers)
	p.exec.runContext(units, 1, workers, op, ctx)
}

func (p *parallelState) ensure(workers int) {
	if workers <= 1 {
		return
	}
	if p.exec != nil && p.exec.workers >= workers {
		return
	}
	p.close()
	p.exec = newParallelExecutor(workers)
}

func manualWorkers(n, blockSize, workers int) (int, error) {
	if workers <= 1 {
		return 0, errx.Wrap(ErrInvalidInput, "workers должно быть больше 1")
	}
	return capWorkers(n, blockSize, workers), nil
}

func capWorkers(n, blockSize, workers int) int {
	if blockSize <= 0 || n <= 0 || workers <= 1 {
		return 1
	}
	blocks := n / blockSize
	if blocks < 2 {
		return 1
	}
	if workers > blocks {
		workers = blocks
	}
	return workers
}

func newParallelExecutor(workers int) *parallelExecutor {
	e := &parallelExecutor{
		workers: workers,
		jobs:    make(chan parallelJob, workers),
		done:    make(chan struct{}, workers),
		stopped: make(chan struct{}, workers),
	}
	for i := 0; i < workers; i++ {
		go e.worker()
	}
	return e
}

func (e *parallelExecutor) worker() {
	var scratch parallelScratch
	for job := range e.jobs {
		if job.stop {
			e.stopped <- struct{}{}
			return
		}
		runParallelOp(job.op, &e.ctx, job.start, job.end, &scratch)
		e.done <- struct{}{}
	}
}

func (e *parallelExecutor) runContext(units, unitSize, workers int, op parallelOp, ctx parallelContext) {
	if units == 0 {
		return
	}
	if workers > e.workers {
		workers = e.workers
	}
	if workers > units {
		workers = units
	}
	if workers <= 1 {
		var scratch parallelScratch
		runParallelOp(op, &ctx, 0, units*unitSize, &scratch)
		return
	}
	e.ctx = ctx
	chunkUnits := (units + workers - 1) / workers
	launched := 0
	for startUnit := 0; startUnit < units; startUnit += chunkUnits {
		endUnit := startUnit + chunkUnits
		if endUnit > units {
			endUnit = units
		}
		launched++
		e.jobs <- parallelJob{
			start: startUnit * unitSize,
			end:   endUnit * unitSize,
			op:    op,
		}
	}
	for i := 0; i < launched; i++ {
		<-e.done
	}
	e.ctx = parallelContext{}
}

func runParallelOp(op parallelOp, ctx *parallelContext, start, end int, scratch *parallelScratch) {
	switch op {
	case parallelOpEncryptBlocks:
		ctx.bulk.EncryptBlocks(ctx.dst[start:end], ctx.src[start:end])
	case parallelOpDecryptBlocks:
		ctx.bulk.DecryptBlocks(ctx.dst[start:end], ctx.src[start:end])
	case parallelOpCBCDecrypt:
		ctx.bulk.DecryptBlocks(ctx.dst[start:end], ctx.src[start:end])
		if start == 0 {
			xorCBCDecryptedChunk(ctx.dst[start:end], ctx.src[start:end], ctx.iv, ctx.blockSize)
			return
		}
		xorCBCDecryptedChunk(ctx.dst[start:end], ctx.src[start:end], ctx.src[start-ctx.blockSize:start], ctx.blockSize)
	case parallelOpCFBDecrypt:
		if start == 0 {
			ctx.block.Encrypt(scratch.gamma[:ctx.blockSize], ctx.iv)
			xorIntoBlock(ctx.dst[:ctx.blockSize], ctx.src[:ctx.blockSize], scratch.gamma[:ctx.blockSize], ctx.blockSize)
			start += ctx.blockSize
		}
		if start < end {
			ctx.bulk.EncryptBlocks(ctx.dst[start:end], ctx.src[start-ctx.blockSize:end-ctx.blockSize])
			xorBlocksInPlace(ctx.dst[start:end], ctx.src[start:end], ctx.blockSize)
		}
	case parallelOpCTR:
		counterForOffset(scratch.counter[:ctx.blockSize], ctx.iv, ctx.blockSize, start/ctx.blockSize)
		xorCTR(ctx.dst[start:end], ctx.src[start:end], ctx.block, ctx.fast, scratch.counter[:ctx.blockSize], scratch.gamma[:ctx.blockSize])
	case parallelOpCTRACPKM:
		c := ctx.acpkm
		for section := start; section < end; section++ {
			offset := section * c.sectionSize
			if offset >= len(ctx.src) {
				break
			}
			sectionLen := min(c.sectionSize, len(ctx.src)-offset)
			counterForOffset(scratch.counter[:c.blockSize], c.iv[:c.blockSize], c.blockSize, offset/c.blockSize)
			xorCTR(
				ctx.dst[offset:offset+sectionLen],
				ctx.src[offset:offset+sectionLen],
				c.blocks[section],
				c.fastBlocks[section],
				scratch.counter[:c.blockSize],
				scratch.gamma[:c.blockSize],
			)
		}
	default:
		panic("gogost/gost3413/modes: некорректная параллельная операция")
	}
}

func (e *parallelExecutor) close() {
	for i := 0; i < e.workers; i++ {
		e.jobs <- parallelJob{stop: true}
	}
	for i := 0; i < e.workers; i++ {
		<-e.stopped
	}
	close(e.jobs)
	close(e.done)
	close(e.stopped)
}

func counterForOffset(counter, iv []byte, blockSize, blockOffset int) {
	normalizeCTRIVInto(counter, iv)
	addCounter(counter[blockSize/2:], blockOffset)
}

func addCounter(counter []byte, blocks int) {
	carry := blocks
	for i := len(counter) - 1; i >= 0 && carry != 0; i-- {
		sum := int(counter[i]) + carry
		counter[i] = byte(sum)
		carry = sum >> 8
	}
}
