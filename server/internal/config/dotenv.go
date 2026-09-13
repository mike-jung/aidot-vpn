// Package config — .env file loader.
//
// We deliberately avoid the popular `joho/godotenv` dependency to keep our
// dependency surface minimal (single dep: the MariaDB driver). The format we
// support is a strict subset of what godotenv accepts and is sufficient for
// AidotVpn's deployment style:
//
//   - lines beginning with `#` are comments, ignored
//   - blank lines are ignored
//   - each non-comment line is `KEY=VALUE`
//   - VALUE may be wrapped in single or double quotes, which are stripped
//   - whitespace around `=` is NOT allowed (POSIX-style: matches docker compose)
//   - VALUE may contain `=` signs (we split on the first `=` only)
//   - we do NOT do shell-style variable expansion (no `$VAR` substitution)
//   - we do NOT process inline comments — the first `#` after VALUE is part
//     of VALUE, matching docker compose behavior
//
// Variables already set in the process environment take precedence over
// values read from the file. This matches the convention of every dotenv
// loader and is critical for production: a Kubernetes secret in env wins
// over a stale committed .env.

package config

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// LoadDotEnv looks for a `.env` file in the current working directory and
// each parent directory up to the filesystem root, loading the first one it
// finds. Missing file is not an error — it simply means the operator chose
// to set environment variables directly.
//
// Returns the absolute path of the file it loaded (or "" if none found),
// a count of variables set, and any error encountered while parsing.
func LoadDotEnv() (path string, count int, err error) {
	if explicit, ok := os.LookupEnv("AIDOTVPN_ENV_FILE"); ok {
		if explicit == "" {
			return "", 0, nil
		}
		if !filepath.IsAbs(explicit) {
			return "", 0, fmt.Errorf("AIDOTVPN_ENV_FILE must be absolute")
		}
		n, parseErr := parseDotEnvFile(explicit)
		return explicit, n, parseErr
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "", 0, fmt.Errorf("getcwd: %w", err)
	}
	return LoadDotEnvFrom(cwd)
}

// LoadDotEnvFrom is the same as LoadDotEnv but starts the search from the
// given directory rather than the process working directory. Useful for
// tests.
func LoadDotEnvFrom(startDir string) (path string, count int, err error) {
	dir := startDir
	for {
		candidate := filepath.Join(dir, ".env")
		info, statErr := os.Stat(candidate)
		if statErr == nil && !info.IsDir() {
			n, parseErr := parseDotEnvFile(candidate)
			if parseErr != nil {
				return candidate, 0, parseErr
			}
			return candidate, n, nil
		}
		if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
			return "", 0, fmt.Errorf("stat %s: %w", candidate, statErr)
		}
		parent := filepath.Dir(dir)
		if parent == dir { // reached filesystem root
			return "", 0, nil
		}
		dir = parent
	}
}

func parseDotEnvFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	count := 0
	sc := bufio.NewScanner(f)
	// Some .env files may have very long lines (cert PEMs etc); raise the
	// default 64 KiB scanner buffer to 1 MiB.
	sc.Buffer(make([]byte, 64*1024), 1024*1024)

	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := sc.Text()

		// Strip a UTF-8 BOM if present on the first line. Notepad on
		// Windows writes one when "Save As → Encoding: UTF-8 with BOM" is
		// chosen, and it'd otherwise break the very first KEY name.
		if lineNum == 1 {
			line = strings.TrimPrefix(line, "\uFEFF")
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// `export FOO=bar` is common shell style; tolerate it.
		trimmed = strings.TrimPrefix(trimmed, "export ")

		eq := strings.IndexByte(trimmed, '=')
		if eq < 0 {
			return count, fmt.Errorf("%s:%d: missing '='", path, lineNum)
		}
		key := strings.TrimSpace(trimmed[:eq])
		value := trimmed[eq+1:]

		if key == "" {
			return count, fmt.Errorf("%s:%d: empty key", path, lineNum)
		}
		if !validEnvKey(key) {
			return count, fmt.Errorf("%s:%d: invalid key %q", path, lineNum, key)
		}

		// Strip surrounding matched quotes. We don't do escape processing
		// inside them; values in our .env do not need it.
		if len(value) >= 2 {
			first, last := value[0], value[len(value)-1]
			if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
				value = value[1 : len(value)-1]
			}
		}

		// Existing env wins. This is critical for production: an operator
		// setting AIDOTVPN_DB_PASSWORD via a secret manager must not be
		// overridden by a leftover dev .env in the working directory.
		if _, alreadySet := os.LookupEnv(key); alreadySet {
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			return count, fmt.Errorf("%s:%d: setenv %s: %w", path, lineNum, key, err)
		}
		count++
	}
	if err := sc.Err(); err != nil {
		return count, fmt.Errorf("read %s: %w", path, err)
	}
	return count, nil
}

// validEnvKey enforces the conservative POSIX-shell rules: alphanumeric and
// underscore only, must not start with a digit. This rejects things like
// `MY KEY` or `MY-KEY=` that some shells would also reject.
func validEnvKey(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_':
			// always allowed
		case r >= 'a' && r <= 'z':
			// always allowed
		case r >= 'A' && r <= 'Z':
			// always allowed
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
