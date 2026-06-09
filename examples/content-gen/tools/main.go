// content-gen-tools is a single mock binary that exposes thirteen
// generative-AI tool endpoints across three modalities (image, audio,
// text — see the `tools` list below for the exact names). It is
// INTENTIONALLY dumb — it accepts any prompt and "returns" a
// deterministic stub response — so the demo can prove that Tool Guard
// denied the call BEFORE this binary ever produced output.
//
// The endpoints accept JSON envelopes with a `prompt` field and (for
// image edits) an optional `source_image_url`. They are deliberately
// MCP-style "one URL per tool name" so the demo is transport-agnostic.
//
// Run:
//
//	go run ./examples/content-gen/tools \
//	  -listen :18091
//
// Endpoints:
//
//	POST /generate_image
//	POST /image_to_image
//	POST /edit_image
//	POST /inpaint_image
//	POST /generate_audio
//	POST /text_to_speech
//	POST /clone_voice
//	POST /generate_music
//	POST /generate_song
//	POST /generate_text
//	POST /complete_chat
//	POST /brainstorm
//	POST /summarise
//
// Each returns the same shape: `{"tool": "<name>", "stub_output":
// "<short message>", "received_prompt": "<echo>"}`. There is no model
// running here — the point is that an unguarded agent could reach
// this surface and "generate" anything, and Tool Guard is what stops
// it.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

type request struct {
	Prompt          string `json:"prompt"`
	NumImages       int    `json:"num_images,omitempty"`
	DurationSeconds int    `json:"duration_seconds,omitempty"`
	MaxTokens       int    `json:"max_tokens,omitempty"`
	SourceImageURL  string `json:"source_image_url,omitempty"`
}

type response struct {
	Tool           string `json:"tool"`
	StubOutput     string `json:"stub_output"`
	ReceivedPrompt string `json:"received_prompt"`
}

// tools is the closed set of endpoints we serve. The names match the
// tool_names in examples/content-gen/policies/*.yaml.
var tools = []string{
	"generate_image", "image_to_image", "edit_image", "inpaint_image",
	"generate_audio", "text_to_speech", "clone_voice", "generate_music", "generate_song",
	"generate_text", "complete_chat", "brainstorm", "summarise",
}

func main() {
	listen := flag.String("listen", ":18091", "host:port to bind")
	flag.Parse()

	mux := http.NewServeMux()
	for _, tool := range tools {
		t := tool
		mux.HandleFunc("/"+t, makeHandler(t))
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "content-gen mock tools")
		fmt.Fprintln(w, "Available endpoints (POST JSON):")
		for _, t := range tools {
			fmt.Fprintln(w, "  /"+t)
		}
	})

	log.Printf("content-gen-tools listening on %s (13 tool endpoints)", *listen)
	if err := http.ListenAndServe(*listen, mux); err != nil {
		log.Fatal(err)
	}
}

func makeHandler(tool string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		var req request
		_ = json.Unmarshal(body, &req)
		// Log so an operator running the demo can see what
		// reached the tool (i.e. what Tool Guard let through).
		log.Printf("tool=%s prompt=%q", tool, truncate(req.Prompt, 80))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response{
			Tool:           tool,
			StubOutput:     fmt.Sprintf("[STUB] %s would produce output here", tool),
			ReceivedPrompt: req.Prompt,
		})
	}
}

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
