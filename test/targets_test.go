package test

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"gitlab.domsnail.ru/domsnail/threat-intel-core/cmd/entities"
	"gitlab.domsnail.ru/domsnail/threat-intel-core/cmd/entities/targets"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"
)

func TestTargets(t *testing.T) {
	t.Run("ip network reservation checks", func(t *testing.T) {
		hosts := []string{
			"192.0.2.1",
			"192.0.2.2",
			"233.252.0.1",
			"240.0.0.2",
			"255.255.255.255",
			"0.0.0.1",
			"127.12.1.2",
			"128.12.1.1",
			"91.122.10.3",
			"91.12.1.1",
			"52.2.1.22",
		}

		require.True(t, targets.CheckIsIPv4Reserved(net.ParseIP(hosts[0])))
		require.True(t, targets.CheckIsIPv4Reserved(net.ParseIP(hosts[1])))
		require.True(t, targets.CheckIsIPv4Reserved(net.ParseIP(hosts[2])))
		require.True(t, targets.CheckIsIPv4Reserved(net.ParseIP(hosts[3])))
		require.True(t, targets.CheckIsIPv4Reserved(net.ParseIP(hosts[4])))
		require.True(t, targets.CheckIsIPv4Reserved(net.ParseIP(hosts[5])))
		require.True(t, targets.CheckIsIPv4Reserved(net.ParseIP(hosts[6])))

		require.False(t, targets.CheckIsIPv4Reserved(net.ParseIP(hosts[7])))
		require.False(t, targets.CheckIsIPv4Reserved(net.ParseIP(hosts[8])))
		require.False(t, targets.CheckIsIPv4Reserved(net.ParseIP(hosts[9])))
		require.False(t, targets.CheckIsIPv4Reserved(net.ParseIP(hosts[10])))
	})

	t.Run("scan target queue creation with domains only", func(t *testing.T) {
		hosts := []string{
			"yandex.ru",
			"ya.ru",
			"mail.ya.ru",
			"mai41sl.fya.r1-u",
			"уцаьзфып.вп.r1-u",
		}

		queue, err := targets.NewScanTargetQueue(hosts, false, false, false, nil)
		require.NoError(t, err)
		require.Len(t, queue.Targets, 5)
	})

	t.Run("scan target queue creation with incorrect domains", func(t *testing.T) {
		hosts := []string{
			"yandex..ru",
			"y!a.ru",
		}

		queue, err := targets.NewScanTargetQueue(hosts, false, false, false, nil)
		require.Error(t, err)
		require.Empty(t, queue.Targets)
	})

	t.Run("scan target queue creation with CIDRs only", func(t *testing.T) {
		hosts := []string{
			"10.10.10.0/32",
			"212.121.122.0/16",
			"2001:4860:4860::8888/32",
		}

		queue, err := targets.NewScanTargetQueue(hosts, false, false, false, nil)
		require.NoError(t, err)
		require.Len(t, queue.Targets, 3)
	})

	t.Run("scan target queue creation with incorrect CIDRs", func(t *testing.T) {
		hosts := []string{
			"256.10.10.0/32",
			"212.121.122.0",
			"2001:4860:4860::8888",
		}

		queue, err := targets.NewScanTargetQueue(hosts, false, false, false, nil)
		require.Error(t, err)
		require.Empty(t, queue.Targets)
	})

	t.Run("scan target queue creation with URLs only", func(t *testing.T) {
		hosts := []string{
			"https://yandex.ru",
			"http://mail.ru",
			"https://mail.yandex.ru",
			"https://user:pass@mail.yandex.ru",
			"//mail.yandex.ru",
			"ftp://ftp.yandex.ru",
			"smb://smb.yandex.ru",
			"https://10.212.12.21/test",
			"https://2001:4860:4860::8888/test",
		}

		queue, err := targets.NewScanTargetQueue(hosts, false, false, false, nil)
		require.NoError(t, err)
		require.Len(t, queue.Targets, 9)
	})

	t.Run("scan target queue creation with URLs forking", func(t *testing.T) {
		hosts := []string{
			"https://yandex.ru",
			"http://mail.ru",
			"https://mail.yandex.ru",
			"https://user:pass@mail.yandex.ru",
			"//mail.yandex.ru",
			"ftp://ftp.yandex.ru",
			"smb://smb.yandex.ru",
			"https://10.212.12.21/test",
			"https://2001:4860:4860::8888/test",
		}

		queue, err := targets.NewScanTargetQueue(hosts, false, true, false, nil)
		require.NoError(t, err)
		require.Len(t, queue.Targets, 9)

		require.NotNil(t, queue.Targets[0].URL)
		require.NotNil(t, queue.Targets[0].Domain)

		require.NotNil(t, queue.Targets[3].URL)
		require.NotNil(t, queue.Targets[3].Domain)

		require.NotNil(t, queue.Targets[7].URL)
		require.NotNil(t, queue.Targets[7].IPNet)
	})

	t.Run("scan target queue creation with URLs forking and shuffling", func(t *testing.T) {
		hosts := []string{
			"https://yandex.ru",
			"http://mail.ru",
			"https://mail.yandex.ru",
			"https://user:pass@mail.yandex.ru",
			"//mail.yandex.ru",
			"ftp://ftp.yandex.ru",
			"smb://smb.yandex.ru",
			"https://10.212.12.21/test",
			"https://2001:4860:4860::8888/test",
		}

		queue, err := targets.NewScanTargetQueue(hosts, true, true, false, nil)
		require.NoError(t, err)
		require.Len(t, queue.Targets, 9)
	})

	t.Run("scan target queue creation with incorrect URLs", func(t *testing.T) {
		hosts := []string{
			"https:/\\mail.yandex.ru",
			"/mail.yandex.ru",
			"/pass@mail.yandex.ru",
		}

		queue, err := targets.NewScanTargetQueue(hosts, false, false, false, nil)
		require.Error(t, err)
		require.Empty(t, queue.Targets)
	})

	t.Run("scan target queue creation with mailboxes only", func(t *testing.T) {
		hosts := []string{
			"yarlrusman@gmail.com",
			"yarlrusman@gmail.mail.com",
		}

		queue, err := targets.NewScanTargetQueue(hosts, false, false, false, nil)
		require.NoError(t, err)
		require.Len(t, queue.Targets, 2)
	})

	t.Run("scan target queue creation with incorrect mailboxes", func(t *testing.T) {
		hosts := []string{
			"test@@mail.ru",
		}

		queue, err := targets.NewScanTargetQueue(hosts, false, false, false, nil)
		require.Error(t, err)
		require.Empty(t, queue.Targets)
	})

	t.Run("scan target queue creation with mailboxes forking", func(t *testing.T) {
		hosts := []string{
			"yarlrusman@gmail.com",
			"yarlrusman@yandex.mail.ru",
		}

		queue, err := targets.NewScanTargetQueue(hosts, false, true, false, nil)
		require.NoError(t, err)
		require.Len(t, queue.Targets, 2)

		require.NotNil(t, queue.Targets[0].Mailbox)
		require.NotNil(t, queue.Targets[0].Domain)

		require.NotNil(t, queue.Targets[1].Mailbox)
		require.NotNil(t, queue.Targets[1].Domain)
	})

	t.Run("scan target queue creation with mixed nodes", func(t *testing.T) {
		hosts := []string{
			"https://yandex.ru",
			"212.122.32.12/32",
			"ya.ru",
			"yarlrusman@yandex.ru",
		}

		queue, err := targets.NewScanTargetQueue(hosts, false, false, false, nil)
		require.NoError(t, err)
		require.Len(t, queue.Targets, 4)

		require.NotNil(t, queue.Targets[0].URL)
		require.NotNil(t, queue.Targets[1].IPNet)
		require.NotNil(t, queue.Targets[2].Domain)
		require.NotNil(t, queue.Targets[3].Mailbox)
	})

	t.Run("scan target queue creation with mixed nodes and errors", func(t *testing.T) {
		hosts := []string{
			"https://yandex.ru",
			"212.122.32.12",
			"ya.ru",
			"/mail.yandex.ru",
			"212.121.122.0",
		}

		queue, err := targets.NewScanTargetQueue(hosts, false, false, false, nil)
		require.Error(t, err)
		require.Len(t, queue.Targets, 1)

		hosts = []string{
			"https://yandex.ru",
			"ya.ru",
			"/mail.yandex.ru",
			"212.122.32.12",
			"212.121.122.0",
		}

		queue, err = targets.NewScanTargetQueue(hosts, false, false, false, nil)
		require.Error(t, err)
		require.Len(t, queue.Targets, 2)
	})

	t.Run("scan target queue expansion", func(t *testing.T) {
		hosts := []string{
			"https://yandex.ru",
			"https://212.122.32.36/path",
			"212.122.32.12/32",
			"ya.ru",
		}

		queue, err := targets.NewScanTargetQueue(hosts, false, true, false, nil)
		require.NoError(t, err)
		require.Len(t, queue.Targets, 4)

		hosts = []string{
			"https://ya.ru",
			"212.122.32.0/16",
		}

		err = queue.Enqueue(hosts, true)
		require.NoError(t, err)
		require.Len(t, queue.Targets, 6)
	})

	t.Run("scan target queue with job id", func(t *testing.T) {
		hosts := []string{
			"https://yandex.ru",
			"https://212.122.32.36/path",
			"212.122.32.12/32",
			"ya.ru",
		}

		var jobID uint64 = 6

		queue, err := targets.NewScanTargetQueue(hosts, false, true, false, &jobID)
		require.NoError(t, err)
		require.Len(t, queue.Targets, 4)

		hosts = []string{
			"https://ya.ru",
			"212.122.32.0/16",
		}

		err = queue.Enqueue(hosts, true)
		require.NoError(t, err)
		require.Len(t, queue.Targets, 6)
	})

	t.Run("scan target queue output", func(t *testing.T) {
		hosts := []string{
			"https://ya.ru",
			"212.122.2.0/16",
		}

		queue, err := targets.NewScanTargetQueue(hosts, false, true, false, nil)
		require.NoError(t, err)
		require.Len(t, queue.Targets, 2)

		tasksChan := make(chan entities.Task, 200)
		var outputTargets []string

		go func() {
			for host := range tasksChan {
				require.NotNil(t, host)
				outputTargets = append(outputTargets, host.Target)
			}
		}()

		queue.Output(tasksChan)
		time.Sleep(4 * time.Second)

		slog.Info(fmt.Sprintf("total targets: %d", len(outputTargets)))

		require.EqualValues(t, "ya.ru", outputTargets[0])
		require.EqualValues(t, "https://ya.ru", outputTargets[1])
		require.EqualValues(t, "212.122.0.1", outputTargets[2])
		require.EqualValues(t, "212.122.0.2", outputTargets[3])
		require.EqualValues(t, "212.122.0.3", outputTargets[4])

		require.Len(t, outputTargets, 65537)
	})

	t.Run("scan target queue output randomized", func(t *testing.T) {
		wg := sync.WaitGroup{}
		wg.Add(1)

		hosts := []string{
			"https://ya.ru",
			"212.122.2.0/16",
		}

		queue, err := targets.NewScanTargetQueue(hosts, true, true, false, nil)
		require.NoError(t, err)
		require.Len(t, queue.Targets, 2)

		tasksChan := make(chan entities.Task, 200)
		var outputTargets []string

		go func() {
			for host := range tasksChan {
				require.NotNil(t, host)
				outputTargets = append(outputTargets, host.Target)
			}
		}()

		queue.Output(tasksChan)
		time.Sleep(4 * time.Second)

		slog.Info(fmt.Sprintf("total targets: %d", len(outputTargets)))

		require.False(t, outputTargets[2] == "212.122.0.1" && outputTargets[3] == "212.122.0.2" && outputTargets[4] == "212.122.0.3")

		require.Len(t, outputTargets, 65537)
	})
}
