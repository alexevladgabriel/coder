//go:build linux || darwin

package boundarylogproxy_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/coder/coder/v2/agent/boundarylogproxy"
	agentproto "github.com/coder/coder/v2/agent/proto"
	"github.com/coder/coder/v2/testutil"
)

// tempDirUnixSocket returns a temporary directory suitable for Unix sockets.
// On macOS, socket paths are limited to ~104 characters, so we use a shorter
// path in /tmp instead of the default temp directory.
func tempDirUnixSocket(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "darwin" {
		// Use a short hash of the test name to keep the path under 104 chars.
		hash := sha256.Sum256([]byte(t.Name()))
		hashStr := hex.EncodeToString(hash[:])[:8]
		dir, err := os.MkdirTemp("/tmp", fmt.Sprintf("c-%s-", hashStr))
		require.NoError(t, err, "create temp dir for unix socket test")
		t.Cleanup(func() {
			err := os.RemoveAll(dir)
			assert.NoError(t, err, "remove temp dir", dir)
		})
		return dir
	}
	return t.TempDir()
}

// sendMessage writes a length-prefixed protobuf message to the connection.
func sendMessage(t *testing.T, conn net.Conn, req *agentproto.ReportBoundaryLogsRequest) {
	t.Helper()

	data, err := proto.Marshal(req)
	if err != nil {
		t.Errorf("%s marshal req: %s", conn.LocalAddr().String(), err)
	}

	err = binary.Write(conn, binary.BigEndian, len(data))
	if err != nil {
		t.Errorf("%s write conn length: %s", conn.LocalAddr().String(), err)
	}

	_, err = conn.Write(data)
	if err != nil {
		t.Errorf("%s write conn data: %s", conn.LocalAddr().String(), err)
	}
}

// fakeReporter implements boundarylogproxy.Reporter for testing.
type fakeReporter struct {
	mu      sync.Mutex
	logs    []*agentproto.ReportBoundaryLogsRequest
	err     error
	errOnce bool // only error once, then succeed

	// reportCb is reportCb when ReportBoundaryLogs is reportCb. It must not
	// block.
	reportCb func()
}

func (f *fakeReporter) ReportBoundaryLogs(_ context.Context, req *agentproto.ReportBoundaryLogsRequest) (*agentproto.ReportBoundaryLogsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.err != nil {
		if f.errOnce {
			err := f.err
			f.err = nil
			return nil, err
		}
		return nil, f.err
	}
	f.logs = append(f.logs, req)

	if f.reportCb != nil {
		f.reportCb()
	}
	return &agentproto.ReportBoundaryLogsResponse{}, nil
}

func (f *fakeReporter) getLogs() []*agentproto.ReportBoundaryLogsRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*agentproto.ReportBoundaryLogsRequest{}, f.logs...)
}

func TestServer_StartAndClose(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(tempDirUnixSocket(t), "boundary.sock")
	srv := boundarylogproxy.NewServer(testutil.Logger(t), socketPath)

	ctx := context.Background()
	err := srv.Start(ctx)
	require.NoError(t, err)

	// Verify socket exists and is connectable.
	conn, err := net.Dial("unix", socketPath)
	require.NoError(t, err)
	err = conn.Close()
	require.NoError(t, err)

	err = srv.Close()
	require.NoError(t, err)
}

func TestServer_StartAlreadyStarted(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(tempDirUnixSocket(t), "boundary.sock")
	srv := boundarylogproxy.NewServer(testutil.Logger(t), socketPath)

	ctx := context.Background()
	err := srv.Start(ctx)
	require.NoError(t, err)
	defer srv.Close()

	// Starting again should fail.
	err = srv.Start(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already started")
}

func TestServer_ReceiveAndForwardLogs(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(tempDirUnixSocket(t), "boundary.sock")
	srv := boundarylogproxy.NewServer(testutil.Logger(t), socketPath)

	ctx, cancel := context.WithTimeout(context.Background(), testutil.WaitShort)
	defer cancel()

	err := srv.Start(ctx)
	require.NoError(t, err)
	defer srv.Close()

	reporter := &fakeReporter{}

	// Start forwarder in background.
	forwarderDone := make(chan error, 1)
	go func() {
		forwarderDone <- srv.RunForwarder(ctx, reporter)
	}()

	// Connect and send a log message.
	conn, err := net.Dial("unix", socketPath)
	require.NoError(t, err)
	defer conn.Close()

	req := &agentproto.ReportBoundaryLogsRequest{
		Logs: []*agentproto.BoundaryLog{
			{
				Allowed: true,
				Time:    timestamppb.Now(),
				Resource: &agentproto.BoundaryLog_HttpRequest_{
					HttpRequest: &agentproto.BoundaryLog_HttpRequest{
						Method: "GET",
						Url:    "https://example.com",
					},
				},
			},
		},
	}

	sendMessage(t, conn, req)

	// Wait for the reporter to receive the log.
	require.Eventually(t, func() bool {
		logs := reporter.getLogs()
		return len(logs) == 1
	}, testutil.WaitShort, testutil.IntervalFast)

	logs := reporter.getLogs()
	require.Len(t, logs, 1)
	require.Len(t, logs[0].Logs, 1)
	require.True(t, logs[0].Logs[0].Allowed)
	require.Equal(t, "GET", logs[0].Logs[0].GetHttpRequest().Method)
	require.Equal(t, "https://example.com", logs[0].Logs[0].GetHttpRequest().Url)

	cancel()
	<-forwarderDone
}

func TestServer_MultipleMessages(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(tempDirUnixSocket(t), "boundary.sock")
	srv := boundarylogproxy.NewServer(testutil.Logger(t), socketPath)

	ctx, cancel := context.WithTimeout(context.Background(), testutil.WaitShort)
	defer cancel()

	err := srv.Start(ctx)
	require.NoError(t, err)
	defer srv.Close()

	reporter := &fakeReporter{}

	forwarderDone := make(chan error, 1)
	go func() {
		forwarderDone <- srv.RunForwarder(ctx, reporter)
	}()

	conn, err := net.Dial("unix", socketPath)
	require.NoError(t, err)
	defer conn.Close()

	// Send multiple messages and verify they are all received.
	for range 5 {
		req := &agentproto.ReportBoundaryLogsRequest{
			Logs: []*agentproto.BoundaryLog{
				{
					Allowed: true,
					Time:    timestamppb.Now(),
					Resource: &agentproto.BoundaryLog_HttpRequest_{
						HttpRequest: &agentproto.BoundaryLog_HttpRequest{
							Method: "POST",
							Url:    "https://example.com/api",
						},
					},
				},
			},
		}
		sendMessage(t, conn, req)
	}

	require.Eventually(t, func() bool {
		logs := reporter.getLogs()
		return len(logs) == 5
	}, testutil.WaitShort, testutil.IntervalFast)

	cancel()
	<-forwarderDone
}

func TestServer_MultipleConnections(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(tempDirUnixSocket(t), "boundary.sock")
	srv := boundarylogproxy.NewServer(testutil.Logger(t), socketPath)

	ctx, cancel := context.WithTimeout(context.Background(), testutil.WaitShort)
	defer cancel()

	err := srv.Start(ctx)
	require.NoError(t, err)
	defer srv.Close()

	reporter := &fakeReporter{}

	forwarderDone := make(chan error, 1)
	go func() {
		forwarderDone <- srv.RunForwarder(ctx, reporter)
	}()

	// Create multiple connections and send from each.
	const numConns = 3
	var wg sync.WaitGroup
	wg.Add(numConns)
	for i := range numConns {
		go func(connID int) {
			defer wg.Done()
			conn, err := net.Dial("unix", socketPath)
			if err != nil {
				t.Errorf("conn %d dial: %s", connID, err)
			}
			defer conn.Close()

			req := &agentproto.ReportBoundaryLogsRequest{
				Logs: []*agentproto.BoundaryLog{
					{
						Allowed: true,
						Time:    timestamppb.Now(),
						Resource: &agentproto.BoundaryLog_HttpRequest_{
							HttpRequest: &agentproto.BoundaryLog_HttpRequest{
								Method: "GET",
								Url:    "https://example.com",
							},
						},
					},
				},
			}
			sendMessage(t, conn, req)
		}(i)
	}
	wg.Wait()

	require.Eventually(t, func() bool {
		logs := reporter.getLogs()
		return len(logs) == numConns
	}, testutil.WaitShort, testutil.IntervalFast)

	cancel()
	<-forwarderDone
}

func TestServer_MessageTooLarge(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(tempDirUnixSocket(t), "boundary.sock")
	srv := boundarylogproxy.NewServer(testutil.Logger(t), socketPath)

	ctx, cancel := context.WithTimeout(context.Background(), testutil.WaitShort)
	defer cancel()

	err := srv.Start(ctx)
	require.NoError(t, err)
	defer srv.Close()

	conn, err := net.Dial("unix", socketPath)
	require.NoError(t, err)
	defer conn.Close()

	// Send a message claiming to be larger than the max message size.
	var length uint32 = 1 << 16
	err = binary.Write(conn, binary.BigEndian, length)
	require.NoError(t, err)

	// The server should close the connection after receiving an oversized
	// message length.
	buf := make([]byte, 1)
	err = conn.SetReadDeadline(time.Now().Add(time.Second))
	require.NoError(t, err)
	_, err = conn.Read(buf)
	require.Error(t, err) // Should get EOF or closed connection.
}

func TestServer_ForwarderContinuesAfterError(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(tempDirUnixSocket(t), "boundary.sock")
	srv := boundarylogproxy.NewServer(testutil.Logger(t), socketPath)

	ctx, cancel := context.WithTimeout(context.Background(), testutil.WaitShort)
	defer cancel()

	err := srv.Start(ctx)
	require.NoError(t, err)
	defer srv.Close()

	reportNotify := make(chan struct{}, 1)
	reporter := &fakeReporter{
		// Simulate an error on the first call.
		err:     context.DeadlineExceeded,
		errOnce: true,
		reportCb: func() {
			reportNotify <- struct{}{}
		},
	}

	forwarderDone := make(chan error, 1)
	go func() {
		forwarderDone <- srv.RunForwarder(ctx, reporter)
	}()

	conn, err := net.Dial("unix", socketPath)
	require.NoError(t, err)
	defer conn.Close()

	// Send the first message to be processed and wait for failure.
	req1 := &agentproto.ReportBoundaryLogsRequest{
		Logs: []*agentproto.BoundaryLog{
			{
				Allowed: true,
				Time:    timestamppb.Now(),
				Resource: &agentproto.BoundaryLog_HttpRequest_{
					HttpRequest: &agentproto.BoundaryLog_HttpRequest{
						Method: "GET",
						Url:    "https://example.com/first",
					},
				},
			},
		},
	}
	sendMessage(t, conn, req1)

	select {
	case <-reportNotify:
	case <-ctx.Done():
		t.Fatal("timed out waiting for first message to be processed")
	}

	// Send the second message, which should succeed.
	req2 := &agentproto.ReportBoundaryLogsRequest{
		Logs: []*agentproto.BoundaryLog{
			{
				Allowed: false,
				Time:    timestamppb.Now(),
				Resource: &agentproto.BoundaryLog_HttpRequest_{
					HttpRequest: &agentproto.BoundaryLog_HttpRequest{
						Method: "POST",
						Url:    "https://example.com/second",
					},
				},
			},
		},
	}
	sendMessage(t, conn, req2)

	// Only the second message should be recorded.
	require.Eventually(t, func() bool {
		logs := reporter.getLogs()
		return len(logs) == 1
	}, testutil.WaitShort, testutil.IntervalFast)

	logs := reporter.getLogs()
	require.Len(t, logs, 1)
	require.Equal(t, "https://example.com/second", logs[0].Logs[0].GetHttpRequest().Url)

	cancel()
	<-forwarderDone
}

func TestServer_CloseStopsForwarder(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(tempDirUnixSocket(t), "boundary.sock")
	srv := boundarylogproxy.NewServer(testutil.Logger(t), socketPath)

	ctx := context.Background()
	err := srv.Start(ctx)
	require.NoError(t, err)

	reporter := &fakeReporter{}

	forwarderCtx, forwarderCancel := context.WithCancel(ctx)
	forwarderDone := make(chan error, 1)
	go func() {
		forwarderDone <- srv.RunForwarder(forwarderCtx, reporter)
	}()

	// Cancel the forwarder context and verify it stops.
	forwarderCancel()

	select {
	case err := <-forwarderDone:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(testutil.WaitShort):
		t.Fatal("forwarder did not stop")
	}

	err = srv.Close()
	require.NoError(t, err)
}

func TestServer_InvalidProtobuf(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(tempDirUnixSocket(t), "boundary.sock")
	srv := boundarylogproxy.NewServer(testutil.Logger(t), socketPath)

	ctx, cancel := context.WithTimeout(context.Background(), testutil.WaitShort)
	defer cancel()

	err := srv.Start(ctx)
	require.NoError(t, err)
	defer srv.Close()

	reporter := &fakeReporter{}

	forwarderDone := make(chan error, 1)
	go func() {
		forwarderDone <- srv.RunForwarder(ctx, reporter)
	}()

	conn, err := net.Dial("unix", socketPath)
	require.NoError(t, err)
	defer conn.Close()

	// Send invalid protobuf data.
	invalidData := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	err = binary.Write(conn, binary.BigEndian, len(invalidData))
	require.NoError(t, err)
	_, err = conn.Write(invalidData)
	require.NoError(t, err)

	// Now send a valid message. The server should continue processing.
	req := &agentproto.ReportBoundaryLogsRequest{
		Logs: []*agentproto.BoundaryLog{
			{
				Allowed: true,
				Time:    timestamppb.Now(),
				Resource: &agentproto.BoundaryLog_HttpRequest_{
					HttpRequest: &agentproto.BoundaryLog_HttpRequest{
						Method: "GET",
						Url:    "https://example.com/valid",
					},
				},
			},
		},
	}
	sendMessage(t, conn, req)

	require.Eventually(t, func() bool {
		logs := reporter.getLogs()
		return len(logs) == 1
	}, testutil.WaitShort, testutil.IntervalFast)

	cancel()
	<-forwarderDone
}

func TestServer_DeniedRequest(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(tempDirUnixSocket(t), "boundary.sock")
	srv := boundarylogproxy.NewServer(testutil.Logger(t), socketPath)

	ctx, cancel := context.WithTimeout(context.Background(), testutil.WaitShort)
	defer cancel()

	err := srv.Start(ctx)
	require.NoError(t, err)
	defer srv.Close()

	reporter := &fakeReporter{}

	forwarderDone := make(chan error, 1)
	go func() {
		forwarderDone <- srv.RunForwarder(ctx, reporter)
	}()

	conn, err := net.Dial("unix", socketPath)
	require.NoError(t, err)
	defer conn.Close()

	// Send a denied request with a matched rule.
	logTime := timestamppb.Now()
	req := &agentproto.ReportBoundaryLogsRequest{
		Logs: []*agentproto.BoundaryLog{
			{
				Allowed: false,
				Time:    logTime,
				Resource: &agentproto.BoundaryLog_HttpRequest_{
					HttpRequest: &agentproto.BoundaryLog_HttpRequest{
						Method:      "GET",
						Url:         "https://malicious.com/attack",
						MatchedRule: "*.malicious.com",
					},
				},
			},
		},
	}
	sendMessage(t, conn, req)

	require.Eventually(t, func() bool {
		logs := reporter.getLogs()
		return len(logs) == 1
	}, testutil.WaitShort, testutil.IntervalFast)

	logs := reporter.getLogs()
	require.Len(t, logs, 1)
	require.False(t, logs[0].Logs[0].Allowed)
	require.Equal(t, logTime, logs[0].Logs[0].Time)
	require.Equal(t, "*.malicious.com", logs[0].Logs[0].GetHttpRequest().MatchedRule)

	cancel()
	<-forwarderDone
}
