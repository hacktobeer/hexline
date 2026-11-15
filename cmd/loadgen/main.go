// Command loadgen drives concurrent SSH sessions against a running board and
// reports latency percentiles. It is a development tool, not part of the BBS.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:2222", "SSH address")
	handle := flag.String("handle", "sysop", "account handle")
	password := flag.String("password", "", "account password (required)")
	sessions := flag.Int("sessions", 50, "concurrent sessions")
	duration := flag.Duration("duration", 20*time.Second, "total run time")
	mode := flag.String("mode", "tui", "tui or auth")
	flag.Parse()

	if *password == "" {
		fmt.Fprintln(os.Stderr, "loadgen: -password is required")
		os.Exit(2)
	}

	cfg := &ssh.ClientConfig{
		User:            *handle,
		Auth:            []ssh.AuthMethod{ssh.Password(*password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	deadline := time.Now().Add(*duration)
	var (
		mu   sync.Mutex
		lat  []time.Duration
		errs int
		ops  int
		wg   sync.WaitGroup
	)
	for i := 0; i < *sessions; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				start := time.Now()
				err := op(*addr, cfg, *mode)
				d := time.Since(start)
				mu.Lock()
				if err != nil {
					errs++
				} else {
					lat = append(lat, d)
				}
				ops++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(lat) == 0 {
		fmt.Printf("no successful operations, %d errors\n", errs)
		os.Exit(1)
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	pct := func(p float64) time.Duration {
		i := int(float64(len(lat)-1) * p)
		return lat[i]
	}
	fmt.Printf("ops=%d errors=%d ok=%d\n", ops, errs, len(lat))
	fmt.Printf("p50=%s p95=%s p99=%s max=%s\n", pct(0.50), pct(0.95), pct(0.99), lat[len(lat)-1])
}

func op(addr string, cfg *ssh.ClientConfig, mode string) error {
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return err
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	if mode == "auth" {
		return sess.Run("whoami")
	}
	modes := ssh.TerminalModes{ssh.ECHO: 1}
	if err := sess.RequestPty("xterm-256color", 24, 80, modes); err != nil {
		return err
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	if err := sess.Shell(); err != nil {
		return err
	}
	time.Sleep(120 * time.Millisecond)
	_, err = io.WriteString(stdin, "?")
	if err != nil {
		return err
	}
	time.Sleep(80 * time.Millisecond)
	_, err = io.WriteString(stdin, "q")
	if err != nil {
		return err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return err
	}
	go io.Copy(io.Discard, stdout)
	done := make(chan struct{})
	go func() { sess.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		return fmt.Errorf("session did not close")
	}
	return nil
}
