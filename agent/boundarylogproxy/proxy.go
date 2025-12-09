// Package boundarylogproxy provides a Unix socket server that receives boundary
// audit logs and forwards them to coderd via the agent API.
//
// Wire Format:
// Boundary sends length-prefixed protobuf messages over the Unix socket (TLV).
// Each message is:
//   - 4 bytes: big-endian uint32 length of the protobuf data
//   - N bytes: protobuf-encoded BoundaryLogsRequest
//
// IMPORTANT: Boundary must generate its proto types with the same field numbers as the
// agent proto (see agent/proto/agent.proto BoundaryLog and ReportBoundaryLogsRequest).
// This is currently done for simplicity while boundary lives in a separate repository.
package boundarylogproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"

	"golang.org/x/xerrors"
	"google.golang.org/protobuf/proto"

	"cdr.dev/slog"
	agentproto "github.com/coder/coder/v2/agent/proto"
)

const (
	// logBufferSize is the size of the channel buffer for incoming log requests
	// from workspaces. This buffer size is intended to handle short bursts of workspaces
	// forwarding batches of logs in parallel.
	logBufferSize = 100
)

// Reporter reports boundary logs from workspaces.
type Reporter interface {
	ReportBoundaryLogs(ctx context.Context, req *agentproto.ReportBoundaryLogsRequest) (*agentproto.ReportBoundaryLogsResponse, error)
}

// Server listens on a Unix socket for boundary log messages and buffers them
// for forwarding to coderd. The socket server and the forwarder are decoupled:
// - Start() creates the socket and begins accepting connections
// - RunForwarder() drains the buffer and sends logs to coderd via the API
//
// This separation allows the socket to remain stable across API reconnections.
type Server struct {
	logger     slog.Logger
	socketPath string

	mu       sync.Mutex
	listener net.Listener
	cancel   context.CancelFunc
	wg       sync.WaitGroup

	// logs buffers incoming log requests for the forwarder to drain.
	logs chan *agentproto.ReportBoundaryLogsRequest
}

// NewServer creates a new boundary log proxy server.
func NewServer(logger slog.Logger, socketPath string) *Server {
	return &Server{
		logger:     logger.Named("boundary-log-proxy"),
		socketPath: socketPath,
		logs:       make(chan *agentproto.ReportBoundaryLogsRequest, logBufferSize),
	}
}

// Start begins listening for connections on the Unix socket.
// Incoming logs are buffered until RunForwarder drains them.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.listener != nil {
		return xerrors.New("server already started")
	}

	if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
		return xerrors.Errorf("remove existing socket: %w", err)
	}

	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return xerrors.Errorf("listen on socket: %w", err)
	}

	s.listener = listener
	ctx, s.cancel = context.WithCancel(ctx)

	s.wg.Add(1)
	go s.acceptLoop(ctx)

	s.logger.Info(ctx, "boundary log proxy started", slog.F("socket_path", s.socketPath))
	return nil
}

// RunForwarder drains the log buffer and forwards logs to coderd.
// This should be called via startAgentAPI to ensure the API client is always
// current and to handle reconnections properly. It blocks until ctx is canceled.
func (s *Server) RunForwarder(ctx context.Context, sender Reporter) error {
	s.logger.Debug(ctx, "boundary log forwarder started")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case req := <-s.logs:
			if _, err := sender.ReportBoundaryLogs(ctx, req); err != nil {
				s.logger.Warn(ctx, "failed to forward boundary logs",
					slog.Error(err),
					slog.F("log_count", len(req.Logs)))
				// Don't return the error - continue forwarding other logs.
				// The current batch is lost but the socket stays alive.
			} else {
				s.logger.Debug(ctx, "forwarded boundary logs", slog.F("log_count", len(req.Logs)))
			}
		}
	}
}

func (s *Server) acceptLoop(ctx context.Context) {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.logger.Warn(ctx, "accept error", slog.Error(err))
			continue
		}

		s.wg.Add(1)
		go s.handleConnection(ctx, conn)
	}
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	// ~32kB provides plenty of headroom given boundary's expected batch queue
	// size of 10 items. This buffer will be re-used rather than allocating a new
	// one for each message received.
	const maxMsgSize = 1 << 15
	buf := make([]byte, maxMsgSize)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		var length uint32
		if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			s.logger.Warn(ctx, "read length error", slog.Error(err))
			return
		}

		if length > maxMsgSize {
			s.logger.Warn(ctx, "message too large", slog.F("length", length))
			return
		}

		if _, err := io.ReadFull(conn, buf[:length]); err != nil {
			s.logger.Warn(ctx, "read body error", slog.Error(err))
			return
		}

		var req agentproto.ReportBoundaryLogsRequest
		if err := proto.Unmarshal(buf[:length], &req); err != nil {
			s.logger.Warn(ctx, "unmarshal error", slog.Error(err))
			continue
		}

		// Buffer the logs for the forwarder. Non-blocking send - drop if full.
		select {
		case s.logs <- &req:
		default:
			s.logger.Warn(ctx, "dropping boundary logs, buffer full",
				slog.F("log_count", len(req.Logs)))
		}
	}
}

// Close stops the server and cleans up resources.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cancel != nil {
		s.cancel()
	}

	if s.listener != nil {
		_ = s.listener.Close()
	}

	s.wg.Wait()

	_ = os.Remove(s.socketPath)
	return nil
}
