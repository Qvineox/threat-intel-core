package main

import (
	"gitlab.domsnail.ru/domsnail/threat-intel-core/cmd/entities"
	"gitlab.domsnail.ru/domsnail/threat-intel-core/cmd/entities/targets"
	"log/slog"
	"strconv"
	"sync"
	"time"
)

func main() {
	wg := sync.WaitGroup{}
	wg.Add(1)

	hosts := []string{
		"https://ya.ru",
		"212.122.32.0/16",
	}

	queue, err := targets.NewScanTargetQueue(hosts, true, true, false, nil)
	if err != nil {
		slog.Error(err.Error())
	}

	tasksChan := make(chan entities.Task, 200)
	var randomTargets []string

	go func() {
		for host := range tasksChan {
			slog.Info(host.Target)

			randomTargets = append(randomTargets, host.Target)
		}
	}()

	queue.Output(tasksChan)
	time.Sleep(2 * time.Second)

	slog.Info(strconv.Itoa(len(randomTargets)))
}
