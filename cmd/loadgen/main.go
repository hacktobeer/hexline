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
		mu      sync.Mutex
		lat     []time.Duration
		keyLat  []time.Duration
		errs    int
		ops     int
		samples []string
		wg      sync.WaitGroup
	)
	for i := 0; i < *sessions; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				start := time.Now()
				key, err := op(*addr, cfg, *mode)
				d := time.Since(start)
				mu.Lock()
				if err == nil && key > 0 {
					keyLat = append(keyLat, key)
				}
				if err != nil {
					errs++
					if len(samples) < 3 {
						samples = append(samples, err.Error())
					}
				} else {
					lat = append(lat, d)
				}
				ops++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	fmt.Printf("ops=%d errors=%d ok=%d\n", ops, errs, len(lat))
	for _, s := range samples {
		fmt.Println("  error:", s)
	}
	if len(lat) == 0 {
		os.Exit(1)
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	pct := func(xs []time.Duration, p float64) time.Duration {
		i := int(float64(len(xs)-1) * p)
		return xs[i]
	}
	fmt.Printf("ops=%d errors=%d ok=%d\n", ops, errs, len(lat))
	for _, s := range samples {
		fmt.Println("  error:", s)
	}
	fmt.Printf("session p50=%s p95=%s p99=%s max=%s\n",
		pct(lat, 0.50), pct(lat, 0.95), pct(lat, 0.99), lat[len(lat)-1])
	if len(keyLat) > 0 {
		sort.Slice(keyLat, func(i, j int) bool { return keyLat[i] < keyLat[j] })
		fmt.Printf("keystroke p50=%s p95=%s p99=%s max=%s\n",
			pct(keyLat, 0.50), pct(keyLat, 0.95), pct(keyLat, 0.99), keyLat[len(keyLat)-1])
	}
}

func op(addr string, cfg *ssh.ClientConfig, mode string) (time.Duration, error) {
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return 0, err
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return 0, err
	}
	defer sess.Close()
	if mode == "auth" {
		return 0, sess.Run("whoami")
	}
	modes := ssh.TerminalModes{ssh.ECHO: 1}
	if err := sess.RequestPty("xterm-256color", 24, 80, modes); err != nil {
		return 0, err
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		return 0, err
	}
	// Consume stdout/stderr through a non-blocking writer: x/crypto requires
	// the streams to be drained before Wait returns, and chunk arrival is our
	// keystroke-to-render proxy.
	chunks := make(chan []byte, 64)
	w := chunkWriter{ch: chunks}
	sess.Stdout = w
	sess.Stderr = w
	if err := sess.Shell(); err != nil {
		return 0, err
	}
	if _, ok := waitChunk(chunks, 3*time.Second); !ok {
		return 0, fmt.Errorf("no initial render")
	}
	if _, err := io.WriteString(stdin, "j"); err != nil {
		return 0, err
	}
	key, ok := waitChunk(chunks, 3*time.Second)
	if !ok {
		return 0, fmt.Errorf("no render after keystroke")
	}
	_ = key
	if _, err := io.WriteString(stdin, "q"); err != nil {
		return 0, err
	}
	done := make(chan struct{})
	go func() { sess.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		return 0, fmt.Errorf("session did not close")
	}
	return key, nil
}

// chunkWriter copies session output into a buffered channel without ever
// blocking the SSH reader; overflow is dropped because this is a load tool.
type chunkWriter struct{ ch chan []byte }

func (w chunkWriter) Write(p []byte) (int, error) {
	b := append([]byte(nil), p...)
	select {
	case w.ch <- b:
	default:
	}
	return len(p), nil
}

// waitChunk waits for the next output chunk and returns how long it took.
func waitChunk(ch <-chan []byte, timeout time.Duration) (time.Duration, bool) {
	start := time.Now()
	select {
	case _, ok := <-ch:
		if !ok {
			return 0, false
		}
		return time.Since(start), true
	case <-time.After(timeout):
		return 0, false
	}
}
