package archive

import "net"

// listenUnixSocket creates a Unix domain socket file at path for tests
// that need a filesystem entry CreateTar cannot represent as a regular
// file, directory, or symlink.
func listenUnixSocket(path string) (net.Listener, error) {
	return net.Listen("unix", path)
}
