//go:build !linux && !darwin

package netw

func init() {
	listConnections = listConnectionsUnsupported
}

// listConnectionsUnsupported covers every platform without a network
// collector in v0.1.0 (notably windows).
func listConnectionsUnsupported() ([]Connection, string, error) {
	return nil, "", errUnsupportedPlatform
}
