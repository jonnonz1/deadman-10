// Package vault seals files or folders into an age-encrypted, gzipped tar and
// opens them again. The switch only ever holds the ciphertext produced here; the
// plaintext is streamed through pipes and never written to a temporary file.
package vault

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

// Seal encrypts the file or directory at src to out for every recipient public
// key. The payload is packed as gzipped tar so a single file and a nested folder
// share one code path and one ciphertext format.
func Seal(src string, recipientKeys []string, out string) (int64, error) {
	recipients, err := parseRecipients(recipientKeys)
	if err != nil {
		return 0, err
	}
	outFile, err := os.Create(out)
	if err != nil {
		return 0, err
	}
	defer outFile.Close()

	encWriter, err := age.Encrypt(outFile, recipients...)
	if err != nil {
		return 0, fmt.Errorf("age encrypt: %w", err)
	}
	gz := gzip.NewWriter(encWriter)
	tw := tar.NewWriter(gz)

	if err := writeTar(tw, src); err != nil {
		return 0, err
	}
	for _, c := range []io.Closer{tw, gz, encWriter} {
		if err := c.Close(); err != nil {
			return 0, err
		}
	}
	info, err := outFile.Stat()
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// Open decrypts the vault at in with identity and extracts its contents under
// destDir, recreating the original file or directory tree.
func Open(in, identityKey, destDir string) error {
	identity, err := age.ParseX25519Identity(identityKey)
	if err != nil {
		return fmt.Errorf("parse identity: %w", err)
	}
	inFile, err := os.Open(in)
	if err != nil {
		return err
	}
	defer inFile.Close()

	decReader, err := age.Decrypt(inFile, identity)
	if err != nil {
		return fmt.Errorf("age decrypt: %w", err)
	}
	gz, err := gzip.NewReader(decReader)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()
	return extractTar(tar.NewReader(gz), destDir)
}

// parseRecipients converts age public key strings into recipients.
func parseRecipients(keys []string) ([]age.Recipient, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("no recipients")
	}
	recipients := make([]age.Recipient, 0, len(keys))
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" || strings.HasPrefix(k, "#") {
			continue
		}
		r, err := age.ParseX25519Recipient(k)
		if err != nil {
			return nil, fmt.Errorf("parse recipient %q: %w", k, err)
		}
		recipients = append(recipients, r)
	}
	return recipients, nil
}

// writeTar adds src (a file or a directory tree) to the tar writer using paths
// relative to src's parent, so extraction reproduces the original layout.
func writeTar(tw *tar.Writer, src string) error {
	base := filepath.Dir(src)
	return filepath.Walk(src, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}
		if !fi.IsDir() && !fi.Mode().IsRegular() {
			return fmt.Errorf("unsupported file %q (mode %v); only regular files and directories can be sealed",
				rel, fi.Mode().Type())
		}
		hdr, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
}

// extractTar writes every tar entry under destDir, rejecting paths that escape
// it (zip-slip protection).
func extractTar(tr *tar.Reader, destDir string) error {
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(destDir, filepath.Clean(hdr.Name))
		if !strings.HasPrefix(target, filepath.Clean(destDir)+string(os.PathSeparator)) &&
			target != filepath.Clean(destDir) {
			return fmt.Errorf("unsafe path in archive: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)&0o777)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		default:
			// Refuse rather than silently drop symlinks/devices/etc, so recovery
			// is never quietly partial.
			return fmt.Errorf("unsupported archive entry %q (type %d); only regular files and directories are supported",
				hdr.Name, hdr.Typeflag)
		}
	}
}
