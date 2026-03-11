// cordova/core/cmd/cordova-vault/util.go

package main

// vaultFilePath joins a mount base directory and a filename into the full path
// to the vault file, e.g. "/mnt/cordova/keys" + "cordova.vault".
func vaultFilePath(mountBase, filename string) string {
	return mountBase + "/" + filename
}

// dirOf returns the directory component of a file path by scanning backwards
// for the last slash. Returns "." if no slash is found.
func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}

// zeroBytes overwrites every byte of b with zero to remove sensitive material
// (passphrases, key bytes) from memory.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
