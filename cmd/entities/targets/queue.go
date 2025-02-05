package targets

import (
	"errors"
	"gitlab.domsnail.ru/domsnail/threat-intel-core/cmd/entities"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
)

type ScanTargetQueue struct {
	Targets []*ScanTarget

	addForked   bool
	useReserved bool
	shuffle     bool

	jobID *uint64

	sync.Mutex
}

// NewScanTargetQueue creates new queue for a scanner, automatically generates targets with type from string slice.
// allowForking defines if domain or ip should be extracted from host.
// allowReserved defines if queue should contain reserved IP addresses.
func NewScanTargetQueue(from []string, shuffle, allowForking, allowReserved bool, jobID *uint64) (*ScanTargetQueue, error) {
	if len(from) == 0 {
		return nil, errors.New("empty target list")
	}

	var t_ *ScanTarget
	var err error

	queue := new(ScanTargetQueue)
	queue.Targets = make([]*ScanTarget, 0, len(from))
	queue.addForked = allowForking
	queue.useReserved = allowReserved
	queue.shuffle = shuffle

	queue.jobID = jobID

	for _, t := range from {
		t_, err = NewScanTarget(AutoTypeScanTarget(t, queue.addForked))
		if err != nil {
			break
		}

		queue.Targets = append(queue.Targets, t_)
	}

	if err != nil {
		return queue, errors.New("failed to create scan queue: " + err.Error())
	}

	if queue.shuffle {
		rand.Shuffle(len(queue.Targets), func(i, j int) {
			queue.Targets[i], queue.Targets[j] = queue.Targets[j], queue.Targets[i]
		})
	}

	return queue, nil
}

func (queue *ScanTargetQueue) Enqueue(from []string, allowForking bool) error {
	queue.Lock()

	if len(from) == 0 {
		return errors.New("empty target list")
	}

	var t_ *ScanTarget
	var err error

	targets_ := make([]*ScanTarget, 0, len(from))

	for _, t := range from {
		t_, err = NewScanTarget(AutoTypeScanTarget(t, allowForking))
		if err != nil {
			break
		}

		targets_ = append(targets_, t_)
	}

	queue.Targets = append(queue.Targets, targets_...)
	queue.Unlock()
	return nil
}

func (queue *ScanTargetQueue) Output(outputChan chan entities.Task) {
	queue.Lock()

	for _, t := range queue.Targets {
		if t.IPNet != nil {
			p, err := netip.ParsePrefix(t.IPNet.String())
			if err != nil {
				slog.Error("failed to parse target ip net: " + err.Error())
				continue
			}

			if queue.shuffle {
				queue.outputIPsShuffled(p, outputChan)
			} else {
				queue.outputIPs(p, outputChan)
			}

			t.IPNet = nil
		}

		if t.Domain != nil {
			outputChan <- entities.Task{
				Target: *t.Domain,
				JobID:  queue.jobID,
			}

			t.Domain = nil
		}

		if t.Mailbox != nil {
			outputChan <- entities.Task{
				Target: t.Mailbox.Address,
				JobID:  queue.jobID,
			}

			t.Mailbox = nil
		}

		if t.URL != nil {
			outputChan <- entities.Task{
				Target: t.URL.String(),
				JobID:  queue.jobID,
			}

			t.URL = nil
		}
	}

	queue.Unlock()
}

func (queue *ScanTargetQueue) produceIPs(network net.IPNet, outputChan chan string, allowReserved bool) error {
	p, err := netip.ParsePrefix(network.String())
	if err != nil {
		return errors.New("failed to parse target ip net: " + err.Error())
	}

	p = p.Masked()
	addr := p.Addr()

	if addr.AsSlice()[3] == 0 {
		addr = addr.Next()
	}

	if allowReserved {
		for {
			if !p.Contains(addr) {
				break
			}

			outputChan <- addr.String()
			addr = addr.Next()
		}
	} else {

	}

	return nil
}

func (queue *ScanTargetQueue) outputIPs(p netip.Prefix, outputChan chan entities.Task) {
	p = p.Masked()
	addr := p.Addr()

	if addr.AsSlice()[3] == 0 {
		addr = addr.Next()
	}

	for {
		if !p.Contains(addr) {
			break
		}

		outputChan <- entities.Task{
			Target: addr.String(),
			JobID:  queue.jobID,
		}

		addr = addr.Next()
	}
}

// 256		for 24-bit subnet
// 65536 	for 16-bit subnet
// 16777214	for  8-bit subnet

const shuffleBucketCap = 65536

func (queue *ScanTargetQueue) outputIPsShuffled(p netip.Prefix, outputChan chan entities.Task) {
	var bucket []netip.Addr

	p = p.Masked()
	addr := p.Addr()

	if addr.AsSlice()[3] == 0 {
		addr = addr.Next()
	}

	keepGoing := true
	for keepGoing {
		for i := 0; i < shuffleBucketCap; i++ {
			if !p.Contains(addr) {
				keepGoing = false
				break
			}

			bucket = append(bucket, addr)
			addr = addr.Next()
		}

		rand.Shuffle(len(bucket), func(i, j int) {
			bucket[i], bucket[j] = bucket[j], bucket[i]
		})

		for _, v := range bucket {
			outputChan <- entities.Task{
				Target: v.String(),
				JobID:  queue.jobID,
			}
		}

		// clear slice with memory allocation
		// ref: https://yourbasic.org/golang/clear-slice/
		bucket = bucket[:0]
	}
}
