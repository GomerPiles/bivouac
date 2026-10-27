package vzbuild

// Windows cannot fsync a directory handle. The builder runs only on macOS;
// its portable parts are still tested on Windows.
func syncDir(string) error { return nil }
