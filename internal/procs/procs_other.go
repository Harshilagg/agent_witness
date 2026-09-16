//go:build !linux && !darwin

package procs

func init() {
	listAll = listAllUnsupported
}

// listAllUnsupported covers every platform without a process collector in
// v0.1.0 (notably windows). Callers must treat Result.Available == false as
// "process collection did not run here", not as "nothing happened".
func listAllUnsupported() ([]rawProc, error) {
	return nil, errUnsupportedPlatform
}
