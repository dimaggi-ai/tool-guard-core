// os-tool is the OS-side backend for the postgres-attack demo.
//
// Like the db-tool, it is intentionally dumb: it executes whatever it
// is told. The only thing protecting the host from a destructive
// `rm -rf /` is tg-proxy in front of this service. If the proxy is
// doing its job, the unsafe paths never reach this binary.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"
)

type errResp struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

type okResp struct {
	OK     bool   `json:"ok"`
	Result any    `json:"result"`
	Note   string `json:"note,omitempty"`
}

func main() {
	listen := flag.String("listen", ":18090", "host:port to bind")
	flag.Parse()

	mux := http.NewServeMux()

	mux.HandleFunc("/os_exec", func(w http.ResponseWriter, r *http.Request) {
		// argv array — NOT a shell-quoted string. The tool exec()s
		// the program directly. No `sh -c`, ever. Shell
		// metacharacters in args are inert because no shell parses
		// them. Closes $IFS, $(), `…`, |, >, glob, etc. as a class.
		var args struct {
			Argv []string `json:"argv"`
		}
		if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
			writeErr(w, fmt.Errorf("bad json: %w", err))
			return
		}
		if len(args.Argv) == 0 {
			writeErr(w, fmt.Errorf("argv must be a non-empty array"))
			return
		}
		log.Printf("os-tool: os_exec argv=%q (this should never appear if the proxy denied it)", args.Argv)
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, args.Argv[0], args.Argv[1:]...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			writeErr(w, fmt.Errorf("exec error: %w; output: %s", err, string(out)))
			return
		}
		writeOK(w, string(out), "command executed (argv exec, no shell)")
	})

	mux.HandleFunc("/os_read_file", func(w http.ResponseWriter, r *http.Request) {
		var args struct {
			Path string `json:"path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
			writeErr(w, fmt.Errorf("bad json: %w", err))
			return
		}
		log.Printf("os-tool: os_read_file %q (proxy bypass if this fires for a sensitive path)", args.Path)
		b, err := os.ReadFile(args.Path)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeOK(w, string(b), fmt.Sprintf("%d bytes", len(b)))
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	log.Printf("os-tool: listening on %s", *listen)
	if err := http.ListenAndServe(*listen, mux); err != nil {
		log.Fatalf("os-tool: %v", err)
	}
}

func writeOK(w http.ResponseWriter, result any, note string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(okResp{OK: true, Result: result, Note: note})
}

func writeErr(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(errResp{OK: false, Error: err.Error()})
}
