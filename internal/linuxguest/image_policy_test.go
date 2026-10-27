package linuxguest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFactorySanitationRejectsJobStateAndRemovesOnlyStartupLogs(t *testing.T) {
	for _, kind := range []string{"empty", "startup", "worker", "work", "credentials", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Mkdir(filepath.Join(root, "_diag"), 0700); err != nil {
				t.Fatal(err)
			}
			path := ""
			switch kind {
			case "startup":
				path = "_diag/Runner_factory.log"
			case "worker":
				path = "_diag/Worker_job.log"
			case "work":
				path = "_work/job"
			case "credentials":
				path = ".credentials"
			case "unknown":
				path = "_diag/unknown.txt"
			}
			if path != "" {
				path = filepath.Join(root, path)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("synthetic"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := sanitizeRunnerFactory(root)
			allowed := kind == "empty" || kind == "startup"
			if (err == nil) != allowed {
				t.Fatal("factory admission differs", err)
			}
			if !allowed {
				if _, e := os.Stat(path); e != nil {
					t.Fatal("refused factory state was removed")
				}
			}
		})
	}
}
