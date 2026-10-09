// Command genmatrix reproduces the canonical Shipovnik H' matrix asset from
// the QAPP reference implementation pinned by shipovnik/NOTICE.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	upstreamURL = "https://raw.githubusercontent.com/QAPP-tech/shipovnik_tc26/a9139ef6178a6dfebac3ae328817a361f0e85256/src/h_prime.c"
	matrixSize  = 262088
	// This checksum is over the row-major H_PRIME byte array, not h_prime.c.
	wantSHA256 = "47571b2e293a0fe90d678341861e9a1080c80c799d3dba6f5964f6dad2a15e62"
)

func main() {
	input := flag.String("input", "", "optional local path to upstream src/h_prime.c")
	output := flag.String("output", "h_prime.bin", "output matrix asset")
	flag.Parse()

	source, err := readSource(*input)
	if err != nil {
		fatal(err)
	}
	matrix, err := extractMatrix(source)
	if err != nil {
		fatal(err)
	}
	sum := sha256.Sum256(matrix)
	if hex.EncodeToString(sum[:]) != wantSHA256 {
		fatal(fmt.Errorf("matrix SHA-256 %x, want %s", sum, wantSHA256))
	}
	if err := os.WriteFile(*output, matrix, 0o644); err != nil {
		fatal(err)
	}
	fmt.Printf("wrote %s (%d bytes, SHA-256 %x)\n", *output, len(matrix), sum)
}

func readSource(path string) ([]byte, error) {
	if path != "" {
		return os.ReadFile(path)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(upstreamURL) // #nosec G107 -- immutable commit URL.
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: %s", upstreamURL, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

func extractMatrix(source []byte) ([]byte, error) {
	marker := []byte("H_PRIME[H_PRIME_SIZE] = {")
	start := bytes.Index(source, marker)
	if start < 0 {
		return nil, fmt.Errorf("H_PRIME initializer not found")
	}
	source = source[start+len(marker):]
	end := bytes.IndexByte(source, '}')
	if end < 0 {
		return nil, fmt.Errorf("unterminated H_PRIME initializer")
	}
	source = source[:end]

	matrix := make([]byte, 0, matrixSize)
	for i := 0; i+3 < len(source); i++ {
		if source[i] != '0' || (source[i+1] != 'x' && source[i+1] != 'X') {
			continue
		}
		var pair [1]byte
		if _, err := hex.Decode(pair[:], source[i+2:i+4]); err != nil {
			return nil, fmt.Errorf("invalid byte at source offset %d: %w", i, err)
		}
		matrix = append(matrix, pair[0])
		i += 3
	}
	if len(matrix) != matrixSize {
		return nil, fmt.Errorf("matrix has %d bytes, want %d", len(matrix), matrixSize)
	}
	return matrix, nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "genmatrix:", err)
	os.Exit(1)
}
