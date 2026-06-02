package transport

import (
	"context"

	"github.com/cerberauth/reportx"
)

// Transport sends a formatted report to a destination.
type Transport interface {
	Send(ctx context.Context, r *reportx.Report, f reportx.Formatter) error
}
