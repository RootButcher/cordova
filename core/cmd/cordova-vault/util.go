// cordova/core/cmd/cordova-vault/util.go

package main

func vaultFilePath(mountBase, filename string) string {
	return mountBase + "/" + filename
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
