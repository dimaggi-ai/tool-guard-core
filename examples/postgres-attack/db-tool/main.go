// db-tool is the real-Postgres backend for the postgres-attack demo.
//
// It exposes one HTTP endpoint per "tool" the agent can call. The tool
// is intentionally dumb: it executes whatever it is told, including
// DROP TABLE. The only thing standing between the LLM and the database
// is tg-proxy in front of this service.
//
// In a real deployment this would be replaced by an MCP server or any
// other tool transport — the policy proxy is layer-agnostic.
package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	_ "github.com/lib/pq"
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
	listen := flag.String("listen", ":18080", "host:port to bind")
	dsn := flag.String("dsn", "host=postgres user=demo password=demo dbname=demo sslmode=disable", "Postgres DSN")
	flag.Parse()

	var db *sql.DB
	var err error
	for i := 0; i < 30; i++ {
		db, err = sql.Open("postgres", *dsn)
		if err == nil {
			if pingErr := db.Ping(); pingErr == nil {
				break
			}
		}
		log.Printf("db-tool: waiting for postgres (%d/30)…", i+1)
		time.Sleep(time.Second)
	}
	if err != nil || db.Ping() != nil {
		log.Fatalf("db-tool: cannot reach postgres: %v", err)
	}
	defer db.Close()
	log.Printf("db-tool: connected to postgres")

	mux := http.NewServeMux()

	mux.HandleFunc("/list_tables", func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query("SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename")
		if err != nil {
			writeErr(w, err)
			return
		}
		defer rows.Close()
		var tables []string
		for rows.Next() {
			var t string
			if err := rows.Scan(&t); err == nil {
				tables = append(tables, t)
			}
		}
		log.Printf("db-tool: list_tables → %v", tables)
		writeOK(w, tables, "")
	})

	mux.HandleFunc("/describe_table", func(w http.ResponseWriter, r *http.Request) {
		var args struct {
			Table string `json:"table"`
		}
		if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
			writeErr(w, fmt.Errorf("bad json: %w", err))
			return
		}
		rows, err := db.Query(`
			SELECT column_name, data_type
			FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = $1
			ORDER BY ordinal_position`, args.Table)
		if err != nil {
			writeErr(w, err)
			return
		}
		defer rows.Close()
		type col struct {
			Name string `json:"name"`
			Type string `json:"type"`
		}
		var cols []col
		for rows.Next() {
			var c col
			if err := rows.Scan(&c.Name, &c.Type); err == nil {
				cols = append(cols, c)
			}
		}
		log.Printf("db-tool: describe_table(%s) → %d columns", args.Table, len(cols))
		writeOK(w, cols, "")
	})

	mux.HandleFunc("/query", func(w http.ResponseWriter, r *http.Request) {
		var args struct {
			SQL string `json:"sql"`
		}
		if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
			writeErr(w, fmt.Errorf("bad json: %w", err))
			return
		}
		// The tool itself is dumb. Policy is enforced at tg-proxy.
		rows, err := db.Query(args.SQL)
		if err != nil {
			writeErr(w, err)
			return
		}
		defer rows.Close()
		cols, _ := rows.Columns()
		var out []map[string]any
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				continue
			}
			row := map[string]any{}
			for i, c := range cols {
				row[c] = stringifyVal(vals[i])
			}
			out = append(out, row)
		}
		log.Printf("db-tool: query → %d rows", len(out))
		writeOK(w, out, fmt.Sprintf("%d rows", len(out)))
	})

	// Destructive endpoints. They will execute if they receive a request.
	// The expectation in this demo is that they never receive one because
	// tg-proxy gates them.
	mux.HandleFunc("/drop_table", func(w http.ResponseWriter, r *http.Request) {
		var args struct {
			Table string `json:"table"`
		}
		if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
			writeErr(w, fmt.Errorf("bad json: %w", err))
			return
		}
		log.Printf("db-tool: DROP TABLE %s (this should never appear if the proxy is doing its job)", args.Table)
		if _, err := db.Exec("DROP TABLE " + quoteIdent(args.Table)); err != nil {
			writeErr(w, err)
			return
		}
		writeOK(w, fmt.Sprintf("dropped %s", args.Table), "destructive op executed")
	})

	mux.HandleFunc("/truncate_table", func(w http.ResponseWriter, r *http.Request) {
		var args struct {
			Table string `json:"table"`
		}
		if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
			writeErr(w, fmt.Errorf("bad json: %w", err))
			return
		}
		log.Printf("db-tool: TRUNCATE %s (proxy bypass!)", args.Table)
		if _, err := db.Exec("TRUNCATE TABLE " + quoteIdent(args.Table)); err != nil {
			writeErr(w, err)
			return
		}
		writeOK(w, fmt.Sprintf("truncated %s", args.Table), "destructive op executed")
	})

	mux.HandleFunc("/delete_rows", func(w http.ResponseWriter, r *http.Request) {
		var args struct {
			Table string `json:"table"`
			Where string `json:"where"`
		}
		if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
			writeErr(w, fmt.Errorf("bad json: %w", err))
			return
		}
		log.Printf("db-tool: DELETE FROM %s WHERE %s (proxy bypass!)", args.Table, args.Where)
		q := "DELETE FROM " + quoteIdent(args.Table)
		if args.Where != "" {
			q += " WHERE " + args.Where
		}
		res, err := db.Exec(q)
		if err != nil {
			writeErr(w, err)
			return
		}
		n, _ := res.RowsAffected()
		writeOK(w, fmt.Sprintf("deleted %d rows from %s", n, args.Table), "destructive op executed")
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	log.Printf("db-tool: listening on %s", *listen)
	if err := http.ListenAndServe(*listen, mux); err != nil {
		log.Fatalf("db-tool: %v", err)
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

func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

func stringifyVal(v any) any {
	switch x := v.(type) {
	case []byte:
		return string(x)
	case time.Time:
		return x.Format(time.RFC3339)
	}
	return v
}
