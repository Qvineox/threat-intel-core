package targets

import (
	_ "embed"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
)

type ScanTargetQueue struct {
	Targets []*ScanTarget

	addForked   bool
	useReserved bool

	sync.Mutex
}

// NewScanTargetQueue creates new queue for a scanner, automatically generates targets with type from string slice.
// AllowForking defines if domain or ip should be extracted from host.
// AllowReserved defines if queue should contain reserved IP addresses.
func NewScanTargetQueue(from []string, allowForking, allowReserved bool) (*ScanTargetQueue, error) {
	if len(from) == 0 {
		return nil, errors.New("empty target list")
	}

	var t_ *ScanTarget
	var err error

	queue := new(ScanTargetQueue)
	queue.Targets = make([]*ScanTarget, 0, len(from))
	queue.addForked = allowForking
	queue.useReserved = allowReserved

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

func (queue *ScanTargetQueue) Output(outputChan chan string) {
	queue.Lock()

	for _, t := range queue.Targets {
		if t.IPNet != nil {
			p, err := netip.ParsePrefix(t.IPNet.String())
			if err != nil {
				slog.Error("failed to parse target ip net: " + err.Error())
				continue
			}

			p = p.Masked()
			addr := p.Addr()

			if addr.AsSlice()[3] == 0 {
				addr = addr.Next()
			}

			for {
				if !p.Contains(addr) {
					break
				}

				outputChan <- addr.String()
				addr = addr.Next()
			}

			t.IPNet = nil
		}

		if t.Domain != nil {
			outputChan <- *t.Domain
			t.Domain = nil
		}

		if t.Mailbox != nil {
			outputChan <- t.Mailbox.Address
			t.Mailbox = nil
		}

		if t.URL != nil {
			outputChan <- t.URL.String()
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
