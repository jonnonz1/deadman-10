package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/jonnonz1/deadman-10/internal/vault"
)

// newKeypair returns a fresh age identity and its recipient public string.
func newKeypair(t *testing.T) (identity string, recipient string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id.String(), id.Recipient().String()
}

// TestSealOpenFile is the core spec: a single file must round-trip byte-exact.
func TestSealOpenFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "secret.txt")
	want := []byte("bank login: hunter2\n")
	if err := os.WriteFile(src, want, 0o600); err != nil {
		t.Fatal(err)
	}
	id, rec := newKeypair(t)
	out := filepath.Join(dir, "vault.age")

	n, err := vault.Seal(src, []string{rec}, out)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if n <= 0 {
		t.Fatalf("Seal returned non-positive size %d", n)
	}

	dest := filepath.Join(dir, "restored")
	if err := vault.Open(out, id, dest); err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "secret.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("round-trip mismatch: got %q want %q", got, want)
	}
}

// TestSealOpenFolder is the new capability: a nested directory tree must
// round-trip with structure and contents intact.
func TestSealOpenFolder(t *testing.T) {
	dir := t.TempDir()
	srcRoot := filepath.Join(dir, "secrets")
	if err := os.MkdirAll(filepath.Join(srcRoot, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"passwords.txt":    "bank: hunter2\n",
		"sub/recovery.txt": "codes: 1234 5678\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(srcRoot, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	id, rec := newKeypair(t)
	out := filepath.Join(dir, "vault.age")
	if _, err := vault.Seal(srcRoot, []string{rec}, out); err != nil {
		t.Fatalf("Seal folder: %v", err)
	}

	dest := filepath.Join(dir, "restored")
	if err := vault.Open(out, id, dest); err != nil {
		t.Fatalf("Open folder: %v", err)
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(dest, "secrets", name))
		if err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
		if string(got) != want {
			t.Errorf("%s: got %q want %q", name, got, want)
		}
	}
}

// TestSealRejectsSymlink proves the folder promise is honest: rather than
// silently corrupting or dropping a symlink, sealing refuses it with a clear
// error, so recovery is never quietly partial.
func TestSealRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	srcRoot := filepath.Join(dir, "secrets")
	if err := os.MkdirAll(srcRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcRoot, "real.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real.txt", filepath.Join(srcRoot, "link.txt")); err != nil {
		t.Skipf("symlinks unsupported here: %v", err)
	}
	_, rec := newKeypair(t)
	_, err := vault.Seal(srcRoot, []string{rec}, filepath.Join(dir, "vault.age"))
	if err == nil {
		t.Fatal("expected Seal to reject a folder containing a symlink")
	}
}

// TestOpenWrongKeyFails proves confidentiality: a non-recipient identity cannot
// decrypt the vault.
func TestOpenWrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, rec := newKeypair(t)
	wrongID, _ := newKeypair(t)
	out := filepath.Join(dir, "vault.age")
	if _, err := vault.Seal(src, []string{rec}, out); err != nil {
		t.Fatal(err)
	}
	if err := vault.Open(out, wrongID, filepath.Join(dir, "restored")); err == nil {
		t.Fatal("expected decryption with wrong key to fail, got nil")
	}
}

// TestMultiRecipient proves any one of several recipients can open the vault
// (owner + beneficiary custody model).
func TestMultiRecipient(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "s.txt")
	if err := os.WriteFile(src, []byte("multi"), 0o600); err != nil {
		t.Fatal(err)
	}
	idA, recA := newKeypair(t)
	idB, recB := newKeypair(t)
	out := filepath.Join(dir, "vault.age")
	if _, err := vault.Seal(src, []string{recA, recB}, out); err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{idA, idB} {
		dest := filepath.Join(dir, "r", string(rune('a'+i)))
		if err := vault.Open(out, id, dest); err != nil {
			t.Errorf("recipient %d could not open: %v", i, err)
		}
	}
}
