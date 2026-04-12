package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LoadDotEnv loads key=value pairs from a .env file into the process
// environment, in the spirit of node.js dotenv. It is intentionally a tiny
// zero-dependency loader (no external module) so the project preserves its
// "no new operational dependencies" posture.
//
// Behavior:
//   - If the file does not exist, returns nil (it is optional).
//   - Existing process env vars are NOT overwritten — anything already
//     exported in the shell wins, matching dotenv's default precedence.
//   - Blank lines and lines beginning with `#` are ignored.
//   - A leading `export ` prefix is stripped so the same file can be
//     `source`d by a shell.
//   - Values may be wrapped in matching single or double quotes; the quotes
//     are stripped. Inline `#` comments after an unquoted value are stripped.
//
// Returns an error only on read/parse failure of an existing file.
func LoadDotEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")

		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			return fmt.Errorf("%s:%d: malformed line, expected KEY=VALUE", path, lineNum)
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])

		// Strip matching surrounding quotes; if the value is unquoted,
		// strip an inline `# comment` so callers can annotate `.env`.
		switch {
		case len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"':
			val = val[1 : len(val)-1]
		case len(val) >= 2 && val[0] == '\'' && val[len(val)-1] == '\'':
			val = val[1 : len(val)-1]
		default:
			if hash := strings.Index(val, " #"); hash >= 0 {
				val = strings.TrimSpace(val[:hash])
			}
		}

		// dotenv precedence: do not overwrite values already exported in
		// the shell. This lets `FOO=bar go run ./cmd/server` keep working.
		if _, present := os.LookupEnv(key); present {
			continue
		}
		if err := os.Setenv(key, val); err != nil {
			return fmt.Errorf("%s:%d: setenv %s: %w", path, lineNum, key, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
