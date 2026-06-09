#!/usr/bin/env bash
# Brute-force bypass suite for tool-guard-core policies.
#
# Each attack declares its expected outcome (denied / allowed). A mismatch
# is either a BYPASS (denied attack got through) or an OVERBLOCK (clean
# call got blocked). The summary at the end counts both.
#
# Prereq: docker compose up -d postgres tg-proxy db-tool os-tool
# Usage:  bash bruteforce-policies.sh
set -eu
PROXY=${PROXY:-http://127.0.0.1:19090/evaluate}

DEFENDED=0
BYPASSED=0
CLEAN=0
OVERBLOCK=0
declare -a FINDINGS=()

probe() {
  local label="$1"
  local body="$2"
  local want="$3"
  local resp got
  resp=$(curl -s -X POST -H 'Content-Type: application/json' -d "$body" "$PROXY")
  got=$(echo "$resp" | jq -r '.action_taken' 2>/dev/null || echo PARSE_ERR)
  if [ "$got" = "$want" ]; then
    if [ "$want" = "denied" ]; then
      printf "  DEFENDED   %-58s -> denied\n" "$label"
      DEFENDED=$((DEFENDED+1))
    else
      printf "  CLEAN      %-58s -> allowed\n" "$label"
      CLEAN=$((CLEAN+1))
    fi
  else
    if [ "$want" = "denied" ] && [ "$got" = "allowed" ]; then
      printf "  *BYPASS*   %-58s -> ALLOWED (expected denied)\n" "$label"
      FINDINGS+=("$label")
      BYPASSED=$((BYPASSED+1))
    elif [ "$want" = "allowed" ] && [ "$got" = "denied" ]; then
      printf "  overblock  %-58s -> denied (expected allowed)\n" "$label"
      OVERBLOCK=$((OVERBLOCK+1))
    else
      printf "  ???        %-58s -> got=%s want=%s\n" "$label" "$got" "$want"
    fi
  fi
}

env() {
  local tool="$1"; local group="$2"; local params="$3"
  cat <<EOF
{"agent_id":"bf","session_id":"bf-test","org_id":"bf","tool_name":"$tool","tool_group":"$group","parameters":$params}
EOF
}

echo "=== A. Canonical SQL keyword regex evasion (every one SHOULD be denied) ==="
probe "DROP TABLE (canonical)"          "$(env query database_ops '{"sql":"DROP TABLE users"}')"             denied
probe "drop table (lowercase)"          "$(env query database_ops '{"sql":"drop table users"}')"             denied
probe "DrOp TaBlE (mixed case)"         "$(env query database_ops '{"sql":"DrOp TaBlE users"}')"             denied
probe "DROP/**/TABLE (SQL block comment)" "$(env query database_ops '{"sql":"DROP/**/TABLE users"}')"        denied
probe "DROP TABLE (preceded by space)"  "$(env query database_ops '{"sql":"   DROP TABLE users"}')"          denied
probe "SELECT 1; DROP TABLE users"      "$(env query database_ops '{"sql":"SELECT 1; DROP TABLE users"}')"   denied
probe "DELETE FROM users (DML)"         "$(env query database_ops '{"sql":"DELETE FROM users"}')"            denied
probe "GRANT ALL ... (DCL)"             "$(env query database_ops '{"sql":"GRANT ALL ON users TO PUBLIC"}')" denied

echo
echo "=== B. SQL evasion via Postgres dollar-quoted EXECUTE ==="
probe "DO \$\$ EXECUTE concat DROP"        "$(env query database_ops '{"sql":"DO $$ BEGIN EXECUTE '"'"'DR'"'"'||'"'"'OP TABLE users'"'"'; END $$;"}')" denied
probe "DO \$\$ EXECUTE concat DELETE"      "$(env query database_ops '{"sql":"DO $$ BEGIN EXECUTE '"'"'DEL'"'"'||'"'"'ETE FROM users'"'"'; END $$;"}')" denied
probe "CREATE FUNCTION ... \$body\$ ..."   "$(env query database_ops '{"sql":"CREATE FUNCTION f() RETURNS void AS $body$ BEGIN EXECUTE '"'"'DROP TABLE users'"'"'; END $body$ LANGUAGE plpgsql;"}')" denied
probe "PREPARE p AS DROP TABLE users"   "$(env query database_ops '{"sql":"PREPARE p AS DROP TABLE users"}')" denied

echo
echo "=== C. Parameter key case mismatch ==="
probe "params.sql DROP (canonical)"     "$(env query database_ops '{"sql":"DROP TABLE x"}')"                 denied
probe "params.SQL DROP (uppercase key)" "$(env query database_ops '{"SQL":"DROP TABLE x"}')"                 denied
probe "params.Sql DROP (capitalized)"   "$(env query database_ops '{"Sql":"DROP TABLE x"}')"                 denied
probe "params.q DROP (different key)"   "$(env query database_ops '{"q":"DROP TABLE x"}')"                   denied

echo
echo "=== D. Tool-name variant spoofing ==="
probe "drop_table (canonical)"          "$(env drop_table database_ops '{"table":"users"}')"                 denied
probe "drop_tables (plural)"            "$(env drop_tables database_ops '{"table":"users"}')"                denied
probe "drop_table_v2 (suffix)"          "$(env drop_table_v2 database_ops '{"table":"users"}')"              denied
probe "DROP_TABLE (uppercase tool)"     "$(env DROP_TABLE database_ops '{"table":"users"}')"                 denied
probe "Drop_Table (mixed case tool)"    "$(env Drop_Table database_ops '{"table":"users"}')"                 denied

echo
echo "=== E. OS exec argv (legacy cmd field is now fail-closed) ==="
probe "argv=[uptime]"                    "$(env os_exec system_ops '{"argv":["uptime"]}')"                   allowed
probe "argv=[ls,-la,/tmp]"               "$(env os_exec system_ops '{"argv":["ls","-la","/tmp"]}')"          allowed
probe "argv=[cat,/var/log/app.log]"      "$(env os_exec system_ops '{"argv":["cat","/var/log/app.log"]}')"   allowed
probe "argv=[rm,-rf,/]"                  "$(env os_exec system_ops '{"argv":["rm","-rf","/"]}')"             denied
probe "argv=[sh,-c,ls]"                  "$(env os_exec system_ops '{"argv":["sh","-c","ls"]}')"             denied
probe "argv=[ls,\$(whoami)]"              "$(env os_exec system_ops '{"argv":["ls","$(whoami)"]}')"           denied
probe "argv=[ls,;rm,-rf]"                "$(env os_exec system_ops '{"argv":["ls",";rm","-rf"]}')"           denied
probe "argv=[find,.,-exec,rm,{},;]"      "$(env os_exec system_ops '{"argv":["find",".","-exec","rm","{}",";"]}')" denied
probe "argv=[cat,/etc/shadow]"           "$(env os_exec system_ops '{"argv":["cat","/etc/shadow"]}')"        denied
probe "argv=[cat,/etc//shadow]"          "$(env os_exec system_ops '{"argv":["cat","/etc//shadow"]}')"       denied
probe "argv=[ls,/proc/self/environ]"     "$(env os_exec system_ops '{"argv":["ls","/proc/self/environ"]}')"  denied
probe "argv=[]"                          "$(env os_exec system_ops '{"argv":[]}')"                            denied
probe "legacy cmd field"                 "$(env os_exec system_ops '{"cmd":"uptime"}')"                      denied

echo
echo "=== F. os_read_file path-traversal / normalization ==="
probe "/etc/shadow (canonical)"         "$(env os_read_file system_ops '{"path":"/etc/shadow"}')"            denied
probe "/etc/../etc/shadow (loopback)"   "$(env os_read_file system_ops '{"path":"/etc/../etc/shadow"}')"     denied
probe "/etc//shadow (double slash)"     "$(env os_read_file system_ops '{"path":"/etc//shadow"}')"           denied
probe "/etc/./shadow (dot slash)"       "$(env os_read_file system_ops '{"path":"/etc/./shadow"}')"          denied
probe "//etc//shadow (multi-slash)"     "$(env os_read_file system_ops '{"path":"//etc//shadow"}')"          denied

echo
echo "=== G. Secret paths not in the regex (info-disclosure gap) ==="
probe "/proc/self/environ"              "$(env os_read_file system_ops '{"path":"/proc/self/environ"}')"     denied
probe "/etc/group (UNIX groups)"        "$(env os_read_file system_ops '{"path":"/etc/group"}')"             denied
probe "~/.docker/config.json"           "$(env os_read_file system_ops '{"path":"/home/alice/.docker/config.json"}')" denied
probe "~/.netrc (HTTP creds)"           "$(env os_read_file system_ops '{"path":"/home/alice/.netrc"}')"     denied
probe "~/.pgpass (postgres creds)"      "$(env os_read_file system_ops '{"path":"/home/alice/.pgpass"}')"    denied
probe "~/.kube/config (k8s creds)"      "$(env os_read_file system_ops '{"path":"/home/alice/.kube/config"}')" denied

echo
echo "──────────────────────────────────────────────────────────────────────"
echo " Defended:  $DEFENDED"
echo " Clean:     $CLEAN"
echo " Bypassed:  $BYPASSED"
echo " Overblock: $OVERBLOCK"
echo "──────────────────────────────────────────────────────────────────────"
if [ "${#FINDINGS[@]}" -gt 0 ]; then
  echo
  echo "  Findings (attacks that ALLOWED but should have DENIED):"
  for f in "${FINDINGS[@]}"; do
    echo "  - $f"
  done
fi
[ "$BYPASSED" -eq 0 ]
