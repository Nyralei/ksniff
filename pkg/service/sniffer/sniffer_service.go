package sniffer

import (
	"context"
	"io"
)

type SnifferService interface {
	// Perform all actions required for starting the remote sniffing
	Setup() error

	// Rollback actions performed during the Setup phase
	Cleanup() error

	// Start remote sniffing, writing capture output to stdOut.
	// Blocks until the context is cancelled or tcpdump exits.
	Start(ctx context.Context, stdOut io.Writer) error
}
