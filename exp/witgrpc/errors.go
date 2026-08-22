package witgrpc

import "fmt"

func wrapErr(err error) error {
	return fmt.Errorf("witgrpc: %w", err)
}
