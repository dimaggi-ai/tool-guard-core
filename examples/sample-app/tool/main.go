// refund-tool is the fake "tool API" the sample agent calls. It does
// nothing real — it just acknowledges refund requests so we can show
// the flow end-to-end: agent → tg-proxy → tool (only when allowed).
//
// In a real deployment this would be your actual refunds service, the
// SQL backend behind execute_sql, the wire-transfer API, etc.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"
)

type refundRequest struct {
	Amount     float64 `json:"amount"`
	CustomerID string  `json:"customer_id"`
	Reason     string  `json:"reason"`
}

type refundResponse struct {
	OK         bool      `json:"ok"`
	TxID       string    `json:"tx_id"`
	Amount     float64   `json:"amount"`
	CustomerID string    `json:"customer_id"`
	ProcessedAt time.Time `json:"processed_at"`
}

func main() {
	listen := flag.String("listen", ":18080", "host:port to bind")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/refund", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req refundRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
		// Pretend to process. Print loudly so the demo run shows that
		// the tool actually executed (it should ONLY print when the
		// proxy allowed the call).
		log.Printf("refund-tool: processing $%.2f for %s (reason=%q)", req.Amount, req.CustomerID, req.Reason)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(refundResponse{
			OK:          true,
			TxID:        fmt.Sprintf("tx-%d", time.Now().UnixNano()),
			Amount:      req.Amount,
			CustomerID:  req.CustomerID,
			ProcessedAt: time.Now().UTC(),
		})
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	log.Printf("refund-tool: listening on %s", *listen)
	if err := http.ListenAndServe(*listen, mux); err != nil {
		log.Fatalf("refund-tool: %v", err)
	}
}
