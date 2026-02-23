package installer

import (
	"bytes"
	"os"
	"runtime"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// NewInstaller
// ---------------------------------------------------------------------------

func TestInstaller_DefaultModelFallback(t *testing.T) {
	inst := NewInstaller("", &bytes.Buffer{})
	if inst.model != defaultModel {
		t.Errorf("model = %q, want %q", inst.model, defaultModel)
	}
}

func TestInstaller_CustomModelSet(t *testing.T) {
	inst := NewInstaller("llama3:70b", &bytes.Buffer{})
	if inst.model != "llama3:70b" {
		t.Errorf("model = %q, want %q", inst.model, "llama3:70b")
	}
}

func TestNewInstaller_Writer(t *testing.T) {
	var buf bytes.Buffer
	inst := NewInstaller("test", &buf)
	if inst.writer != &buf {
		t.Error("expected writer to be the provided buffer")
	}
}

// ---------------------------------------------------------------------------
// Installer.log
// ---------------------------------------------------------------------------

func TestInstallerLog_Simple(t *testing.T) {
	var buf bytes.Buffer
	inst := NewInstaller("test", &buf)
	inst.log("hello %s", "world")

	got := buf.String()
	if got != "hello world\n" {
		t.Errorf("log output = %q, want %q", got, "hello world\n")
	}
}

func TestInstallerLog_Multiple(t *testing.T) {
	var buf bytes.Buffer
	inst := NewInstaller("test", &buf)
	inst.log("line1")
	inst.log("line2 %d", 42)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	if lines[0] != "line1" {
		t.Errorf("line 0 = %q", lines[0])
	}
	if lines[1] != "line2 42" {
		t.Errorf("line 1 = %q", lines[1])
	}
}

// ---------------------------------------------------------------------------
// NewUninstaller
// ---------------------------------------------------------------------------

func TestNewUninstaller(t *testing.T) {
	var buf bytes.Buffer
	u := NewUninstaller(&buf)
	if u == nil {
		t.Fatal("expected non-nil uninstaller")
	}
	if u.writer != &buf {
		t.Error("writer not set correctly")
	}
}

// ---------------------------------------------------------------------------
// Uninstaller.log
// ---------------------------------------------------------------------------

func TestUninstallerLog(t *testing.T) {
	var buf bytes.Buffer
	u := NewUninstaller(&buf)
	u.log("removing %s", "binary")

	got := buf.String()
	if got != "removing binary\n" {
		t.Errorf("log output = %q, want %q", got, "removing binary\n")
	}
}

// ---------------------------------------------------------------------------
// ollamaDataDirs
// ---------------------------------------------------------------------------

func TestOllamaDataDirs_CurrentOS(t *testing.T) {
	var buf bytes.Buffer
	u := NewUninstaller(&buf)
	dirs := u.ollamaDataDirs()

	// Should return at least one directory on any platform
	if len(dirs) == 0 {
		t.Error("expected at least one data directory")
	}

	// On darwin/linux, should include ~/.ollama
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		home, _ := os.UserHomeDir()
		if home != "" {
			found := false
			for _, d := range dirs {
				if strings.HasSuffix(d, ".ollama") {
					found = true
					break
				}
			}
			if !found {
				t.Error("expected .ollama dir in list")
			}
		}
	}
}

func TestOllamaDataDirs_WithModelsEnv(t *testing.T) {
	var buf bytes.Buffer
	u := NewUninstaller(&buf)

	t.Setenv("OLLAMA_MODELS", "/custom/models/path")
	dirs := u.ollamaDataDirs()

	found := false
	for _, d := range dirs {
		if d == "/custom/models/path" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected OLLAMA_MODELS env path in dirs")
	}
}

func TestOllamaDataDirs_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only test")
	}
	var buf bytes.Buffer
	u := NewUninstaller(&buf)
	dirs := u.ollamaDataDirs()

	found := false
	for _, d := range dirs {
		if d == "/usr/share/ollama" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected /usr/share/ollama in linux data dirs")
	}
}
