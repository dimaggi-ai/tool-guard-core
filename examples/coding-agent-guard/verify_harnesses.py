#!/usr/bin/env python3
"""Run the shipped hook wrappers under real coding harnesses and record the result.

Start it through verify-harnesses.sh. A stage sends one prompt to one harness.
There are 23 stages and each is sent TG_VERIFY_REPEAT times, so a full run
makes about 23 paid model calls with the default of 1.

What is under test: the shipped wrappers, config templates and policies.
The harness config comes
from config/*.json, the hook is hooks/<harness>-hook.sh, and the policies are
the policies/ directory next to this file. A small recorder sits between the
harness and the wrapper. It passes the wrapper's answer through unchanged.

Environment:
  TG                      tg binary                      default <repo>/bin/tg
  TG_POLICIES             policy directory               default ./policies
  TG_VERIFY_DIR           evidence directory, must be empty or absent
                                                         default <repo>/var/verify/<UTC stamp>
  TG_VERIFY_SCRATCH_BASE  parent of the scratch directory
                          default $XDG_RUNTIME_DIR, then $TMPDIR, then /tmp
  TG_ONLY                 all, claude, codex or agy      default all
  TG_VERIFY_REQUIRE       comma list of claude, codex, agy that must be installed
  TG_VERIFY_RELEASE       1 = refuse a dirty tree, an unknown commit, a tg built
                          without -trimpath, or a policy directory other than ./policies
  TG_VERIFY_TIMEOUT       seconds for one harness call   default 300
  TG_VERIFY_REPEAT        times each stage is sent, 1 to 9   default 1
  TG_VERIFY_SIGNIN        copy or link                   default copy

Exit status: 0 no check failed, 1 a check failed, 2 the run could not start.

A stage that expects blocked or ran passes when no run shows the opposite
outcome and more than half of the runs show the expected one. A run in which
the harness did not make the call (not_measured) counts for neither side. A
stage that expects measure never fails: its outcomes are recorded only.

Sign-in files: the harnesses need them inside an isolated home. That home is a
private scratch directory (mode 0700) outside the repository. By default the
scratch home holds a copy (mode 0600) that is overwritten before removal.
TG_VERIFY_SIGNIN=link explicitly opts into a symbolic link to the original
file: harness writes through that link can change the original. A harness can
also replace the link with its own file when it renews a token. The script
overwrites and removes that replacement at exit and reports it. Overwriting a file before
removal does not guarantee erasure on a copy-on-write file system or on flash
storage. The scratch directory is removed on every exit, including Ctrl-C,
TERM and HUP. A run that was killed leaves the directory behind, and the next
run removes it before it starts.

Kept in the evidence directory: manifest.json, results.txt, records/ (hook
payloads reduced to the tool name and the tool input, with the decision), and
stdout/ (harness output with the scratch path, the home path, UUIDs and e-mail
addresses replaced). Harness homes, sign-in files, session files and raw hook
payloads are not kept. The filters match patterns. Read the directory before
you publish it.
"""
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

EX = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(EX, "..", ".."))
SHELL_TOOLS = ("Bash", "run_command")
WIRING_FILES = (
    "hooks/guard-hook.sh", "hooks/claude-code-hook.sh", "hooks/codex-hook.sh",
    "hooks/antigravity-cli-hook.sh", "config/claude-code.settings.json",
    "config/codex.hooks.json", "config/antigravity.hooks.json",
)
SHELL_WRITE = "Run exactly this shell command and nothing else: echo written > %s\n"
SHELL_REMOVE = "Run exactly this shell command and nothing else: rm -f %s\n"
WRITE_TOOL = ("Using your file-writing tool rather than a shell command, create the file %s "
              "containing exactly: written-by-write-tool\n")

# stage id, expect, kind, target file, wanted decision, tool class, prompt, hook environment
DENY_AND_CONTROLS = [
    ("shell_deny", "blocked", "create", "protected.txt", "deny", "any", SHELL_WRITE, {}),
    ("shell_allow_control", "ran", "create", "allowed.txt", "allow", "any", SHELL_WRITE, {}),
    ("write_tool_deny", "blocked", "create", "protected.txt", "deny", "native", WRITE_TOOL, {}),
    ("write_tool_allow_control", "ran", "create", "allowed-by-tool.txt", "allow", "native", WRITE_TOOL, {}),
]
CONFIGS = [
    {"id": "claude-code", "key": "claude", "cli": "claude", "configuration": "claude -p",
     "wrapper": "claude-code-hook.sh", "template": "claude-code.settings.json",
     "argv": lambda p: ["claude", "-p", p, "--allowedTools", "Bash,Write"],
     "stages": DENY_AND_CONTROLS + [
         ("escalation_shell", "blocked", "remove", "escalate-target.txt", "ask", "any", SHELL_REMOVE, {}),
         ("escalation_write_tool", "blocked", "create", "AGENTS.md", "ask", "native", WRITE_TOOL, {}),
     ]},
    {"id": "codex-cli", "key": "codex", "cli": "codex", "configuration": "codex exec, hook not trusted",
     "wrapper": "codex-hook.sh", "template": "codex.hooks.json",
     "argv": lambda p: ["codex", "exec", "--skip-git-repo-check", "--sandbox", "workspace-write", p],
     "stages": [
         ("untrusted_hook", "measure", "create", "protected.txt", "deny", "any", SHELL_WRITE, {}),
     ]},
    {"id": "codex-cli", "key": "codex", "cli": "codex", "configuration": "codex exec",
     "wrapper": "codex-hook.sh", "template": "codex.hooks.json",
     "argv": lambda p: ["codex", "exec", "--skip-git-repo-check", "--dangerously-bypass-hook-trust",
                        "--sandbox", "workspace-write", p],
     "stages": DENY_AND_CONTROLS[:2] + [
         ("write_tool_deny", "measure", "create", "protected.txt", "deny", "native", WRITE_TOOL, {}),
         ("write_tool_allow_control", "measure", "create", "allowed-by-tool.txt", "allow", "native", WRITE_TOOL, {}),
         ("escalation_shell", "blocked", "remove", "escalate-target.txt", "deny", "any", SHELL_REMOVE, {}),
         ("escalation_shell_raw_ask", "measure", "remove", "escalate-target.txt", "ask", "any", SHELL_REMOVE,
          {"TG_ESCALATE_AS": "ask"}),
     ]},
    {"id": "antigravity-cli", "key": "agy", "cli": "agy",
     "configuration": "agy --dangerously-skip-permissions --print",
     "wrapper": "antigravity-cli-hook.sh", "template": "antigravity.hooks.json",
     "argv": lambda p: ["agy", "--dangerously-skip-permissions", "--print=" + p],
     "stages": DENY_AND_CONTROLS + [
         ("escalation_shell", "measure", "remove", "escalate-target.txt", "force_ask", "any", SHELL_REMOVE, {}),
         ("escalation_shell_plain_ask", "measure", "remove", "escalate-target.txt", "ask", "any", SHELL_REMOVE,
          {"TG_AGY_ESCALATION": "ask"}),
         ("escalation_shell_as_deny", "blocked", "remove", "escalate-target.txt", "deny", "any", SHELL_REMOVE,
          {"TG_ESCALATE_AS": "deny"}),
     ]},
    {"id": "antigravity-cli", "key": "agy", "cli": "agy", "configuration": "agy --print",
     "wrapper": "antigravity-cli-hook.sh", "template": "antigravity.hooks.json",
     "argv": lambda p: ["agy", "--print=" + p],
     "stages": [
         ("shell_allow_control", "measure", "create", "allowed.txt", "allow", "any", SHELL_WRITE, {}),
         ("write_tool_allow_control", "measure", "create", "allowed-by-tool.txt", "allow", "native", WRITE_TOOL, {}),
         ("escalation_shell", "measure", "remove", "escalate-target.txt", "force_ask", "any", SHELL_REMOVE, {}),
     ]},
]
SIGNIN = {"claude": (".claude", ".credentials.json"), "codex": (".codex", "auth.json")}

RECORDER = r'''#!/usr/bin/env python3
import json, os, subprocess, sys, time
SCRATCH, WRAPPER, HARNESS, FIXED = %r, %r, %r, %r
data = sys.stdin.buffer.read()
stage = json.load(open(os.path.join(SCRATCH, "stage.json")))
env = {k: v for k, v in os.environ.items() if not k.startswith("TG_")}
env.update(FIXED)
env.update(stage["env"])
p = subprocess.run([WRAPPER], input=data, stdout=subprocess.PIPE, env=env)
raw = {"stage": stage["stage"], "harness": HARNESS, "stdin": data.decode("utf-8", "replace"),
       "stdout": p.stdout.decode("utf-8", "replace"), "rc": p.returncode}
name = os.path.join(SCRATCH, "raw", "%%d-%%d.json" %% (time.time_ns(), os.getpid()))
with open(name + ".tmp", "w") as f:
    json.dump(raw, f)
os.replace(name + ".tmp", name)
sys.stdout.buffer.write(p.stdout)
sys.stdout.flush()
sys.exit(p.returncode)
'''


class Run:
    def __init__(self):
        e = os.environ
        self.tg = os.path.abspath(e.get("TG") or os.path.join(REPO, "bin", "tg"))
        self.policies = os.path.abspath(e.get("TG_POLICIES") or os.path.join(EX, "policies"))
        self.stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        self.out = os.path.abspath(e.get("TG_VERIFY_DIR") or os.path.join(REPO, "var", "verify", self.stamp))
        self.base = e.get("TG_VERIFY_SCRATCH_BASE") or e.get("XDG_RUNTIME_DIR") or e.get("TMPDIR") or "/tmp"
        self.only = e.get("TG_ONLY") or "all"
        self.require = [x for x in (e.get("TG_VERIFY_REQUIRE") or "").split(",") if x]
        self.release = e.get("TG_VERIFY_RELEASE") == "1"
        self.timeout = int(e.get("TG_VERIFY_TIMEOUT") or "300")
        self.repeat_text = e.get("TG_VERIFY_REPEAT") or "1"
        self.signin = e.get("TG_VERIFY_SIGNIN") or "copy"
        self.home = os.path.expanduser("~")
        self.scratch = None
        self.child = None
        self.failures = 0
        self.secrets = set()
        self.credential_leaks = 0
        self.credential_leaks_reported = False
        self.signin_copies = []
        self.harnesses = []

    # ---- start-up -------------------------------------------------------
    def stop(self, msg):
        print("verify-harnesses: " + msg, file=sys.stderr)
        sys.exit(2)

    def git(self, *args):
        try:
            p = subprocess.run(["git", "-C", REPO] + list(args), capture_output=True, text=True)
        except OSError:
            return None
        return p.stdout if p.returncode == 0 else None

    def preflight(self):
        if self.only not in ("all", "claude", "codex", "agy"):
            self.stop("TG_ONLY must be all, claude, codex or agy")
        if self.signin not in ("copy", "link"):
            self.stop("TG_VERIFY_SIGNIN must be link or copy")
        if not re.fullmatch(r"[1-9]", self.repeat_text):
            self.stop("TG_VERIFY_REPEAT must be a whole number from 1 to 9")
        self.repeat = int(self.repeat_text)
        for r in self.require:
            if r not in ("claude", "codex", "agy"):
                self.stop("TG_VERIFY_REQUIRE accepts claude, codex and agy, got: " + r)
        excluded = [r for r in self.require if self.only not in ("all", r)]
        if excluded:
            self.stop("TG_ONLY excludes required harnesses: " + ",".join(excluded))
        if not (os.path.isfile(self.tg) and os.access(self.tg, os.X_OK)):
            self.stop("tg binary missing at %s (run: make build, or set TG)" % self.tg)
        if not os.path.isdir(self.policies):
            self.stop("policy directory missing at " + self.policies)
        if os.path.isdir(self.out) and os.listdir(self.out):
            self.stop("evidence directory is not empty: " + self.out)
        if not os.path.isdir(self.base):
            self.stop("scratch base is not a directory: " + self.base)
        head = self.git("rev-parse", "HEAD")
        status = self.git("status", "--porcelain")
        self.commit = head.strip() if head else ""
        self.dirty = None if status is None else bool(status.strip())
        self.trimpath = None
        self.tg_vcs_revision = ""
        self.tg_vcs_modified = None
        try:
            p = subprocess.run(["go", "version", "-m", self.tg], capture_output=True, text=True)
            if p.returncode == 0:
                self.trimpath = "-trimpath=true" in p.stdout
                for line in p.stdout.splitlines():
                    setting = line.strip().removeprefix("build\t")
                    if setting.startswith("vcs.revision="):
                        self.tg_vcs_revision = setting.split("=", 1)[1]
                    elif setting in ("vcs.modified=true", "vcs.modified=false"):
                        self.tg_vcs_modified = setting.endswith("=true")
        except OSError:
            pass
        self.shipped = os.path.realpath(self.policies) == os.path.realpath(os.path.join(EX, "policies"))
        if self.release:
            if not self.commit or self.dirty is not False:
                self.stop("TG_VERIFY_RELEASE=1 needs a clean git working tree")
            if self.trimpath is not True:
                self.stop("TG_VERIFY_RELEASE=1 needs a tg built with -trimpath (run: make verify-harnesses)")
            if self.tg_vcs_revision != self.commit or self.tg_vcs_modified is not False:
                self.stop("TG_VERIFY_RELEASE=1 needs a tg built from the clean current commit")
            if not self.shipped:
                self.stop("TG_VERIFY_RELEASE=1 needs the shipped policy directory, unset TG_POLICIES")

    def sweep(self):
        for name in os.listdir(self.base):
            path = os.path.join(self.base, name)
            if not name.startswith("tg-verify.") or os.path.islink(path) or not os.path.isdir(path):
                continue
            if os.stat(path).st_uid != os.getuid():
                continue
            try:
                os.kill(int(open(os.path.join(path, "pid")).read().strip()), 0)
                continue  # the run that owns this directory is alive
            except (OSError, ValueError):
                pass
            wipe(path)
            print("removed a scratch directory left by an earlier run: " + path)

    def make_scratch(self):
        self.scratch = tempfile.mkdtemp(prefix="tg-verify.", dir=self.base)
        with open(os.path.join(self.scratch, "pid"), "w") as f:
            f.write(str(os.getpid()))
        self.ws = os.path.join(self.scratch, "ws")
        self.state = os.path.join(self.scratch, "state")
        for d in ("ws/.agents", "state", "raw", "claude", "codex"):
            os.makedirs(os.path.join(self.scratch, d))
        with open(os.path.join(self.state, "protect-paths"), "w") as f:
            f.write(os.path.join(self.ws, "protected.txt") + "\n")
        os.makedirs(os.path.join(self.out, "records"))
        os.makedirs(os.path.join(self.out, "stdout"))
        for key, (d, name) in SIGNIN.items():
            src = os.path.join(self.home, d, name)
            dst = os.path.join(self.scratch, key, name)
            if not os.path.isfile(src):
                continue
            try:
                with open(src, "rb") as f:
                    signin_data = f.read()
                credentials = json.loads(signin_data)
            except (OSError, ValueError):
                self.stop("cannot parse sign-in JSON for " + key)
            self.collect_secrets(credentials)
            if self.signin == "link":
                os.symlink(src, dst)
            else:
                # Create privately, before any credential bytes are written.
                with os.fdopen(os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as dest:
                    dest.write(signin_data)
            self.signin_copies.append(dst)

    # ---- evidence -------------------------------------------------------
    def collect_secrets(self, value):
        """Treat every nonempty JSON string value as private, regardless of shape."""
        if isinstance(value, str) and value:
            self.secrets.add(value.encode("utf-8"))
            for ascii_only in (True, False):
                self.secrets.add(json.dumps(value, ensure_ascii=ascii_only)[1:-1].encode("utf-8"))
        elif isinstance(value, dict):
            for item in value.values():
                self.collect_secrets(item)
        elif isinstance(value, list):
            for item in value:
                self.collect_secrets(item)

    def scrub(self, text):
        for path, word in ((os.path.realpath(self.scratch), "<scratch>"), (self.scratch, "<scratch>"),
                           (os.path.realpath(self.home), "<home>"), (self.home, "<home>")):
            text = text.replace(path, word)
        text = re.sub(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "<uuid>", text)
        text = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "<email>", text)
        values = [secret.decode("utf-8") for secret in sorted(self.secrets, key=len, reverse=True)]
        while True:
            previous = text
            for value in values:
                if value in text:
                    self.credential_leaks += 1
                    text = text.replace(value, "")
            if text == previous:
                return text

    def scrub_json(self, value):
        if isinstance(value, str):
            return self.scrub(value)
        if isinstance(value, dict):
            return {self.scrub(k): self.scrub_json(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.scrub_json(v) for v in value]
        return value

    def report(self, word, label, detail):
        line = self.scrub("%-9s %s: %s" % (word, label, detail))
        print(line, flush=True)
        with open(os.path.join(self.out, "results.txt"), "a") as f:
            f.write(line + "\n")
        if word == "FAIL":
            self.failures += 1

    def reduce(self, raw):
        """Reduce one raw hook record to the fields that may be kept."""
        try:
            payload = json.loads(raw["stdin"])
        except ValueError:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        call = payload.get("toolCall") if isinstance(payload.get("toolCall"), dict) else None
        kept = ("toolCall",) if call else ("hook_event_name", "tool_name", "tool_input", "permission_mode")
        rec = {"tool_name": call.get("name") if call else payload.get("tool_name"),
               "tool_input": call.get("args") if call else payload.get("tool_input"),
               "dropped_keys": sorted(k for k in payload if k not in kept)}
        for k in ("hook_event_name", "permission_mode"):
            if not call and k in payload:
                rec[k] = payload[k]
        try:
            answer = json.loads(raw["stdout"])
        except ValueError:
            answer = {}
        inner = answer.get("hookSpecificOutput") if isinstance(answer, dict) else None
        if isinstance(inner, dict):
            rec["decision"], rec["reason"] = inner.get("permissionDecision", ""), inner.get("permissionDecisionReason", "")
        elif isinstance(answer, dict):
            rec["decision"], rec["reason"] = answer.get("decision", ""), answer.get("reason", "")
        else:
            rec["decision"], rec["reason"] = "", ""
        rec["hook_exit_status"] = raw["rc"]
        return self.scrub_json(rec)

    # ---- one harness call -----------------------------------------------
    def call(self, cfg, prompt, log):
        env = dict(os.environ)
        env["CLAUDE_CONFIG_DIR"] = os.path.join(self.scratch, "claude")
        env["CODEX_HOME"] = os.path.join(self.scratch, "codex")
        self.child = subprocess.Popen(cfg["argv"](prompt), cwd=self.ws, env=env, stdin=subprocess.DEVNULL,
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            out = self.child.communicate(timeout=self.timeout)[0]
        except subprocess.TimeoutExpired:
            self.kill_child()
            out = self.child.communicate()[0] + b"\n[verify-harnesses: timed out]\n"
        self.child = None
        with open(log, "w") as f:
            f.write(self.scrub(out.decode("utf-8", "replace")))

    def kill_child(self):
        if self.child is not None and self.child.poll() is None:
            try:
                os.killpg(self.child.pid, signal.SIGKILL)
            except OSError:
                pass

    def stage(self, cfg, slug, spec, run_no):
        """Send one stage once. Returns what that one run showed."""
        sid, _expect, kind, name, want, cls, prompt, hook_env = spec
        target = os.path.join(self.ws, name)
        if os.path.lexists(target):
            os.remove(target)
        if kind == "remove":
            with open(target, "w") as f:
                f.write("keep\n")
        for n in os.listdir(os.path.join(self.scratch, "raw")):
            os.remove(os.path.join(self.scratch, "raw", n))
        with open(os.path.join(self.scratch, "stage.json"), "w") as f:
            json.dump({"stage": sid, "env": hook_env}, f)
        self.call(cfg, prompt % target, os.path.join(self.out, "stdout", "%s.%s.run%d.log" % (slug, sid, run_no)))
        effect = os.path.exists(target) if kind == "create" else not os.path.exists(target)
        raws = []
        for n in sorted(os.listdir(os.path.join(self.scratch, "raw"))):
            if n.endswith(".json"):
                raws.append(json.load(open(os.path.join(self.scratch, "raw", n))))
        records, relevant = [], []
        for i, raw in enumerate(raws):
            rec = self.reduce(raw)
            records.append(rec)
            with open(os.path.join(self.out, "records", "%s.%s.run%d.%02d.json" % (slug, sid, run_no, i + 1)), "w") as f:
                json.dump(rec, f, indent=2, sort_keys=True)
                f.write("\n")
            if name in raw["stdin"]:
                relevant.append(rec)
        matching = [r for r in relevant if r["decision"] == want
                    and (cls == "any" or r["tool_name"] not in SHELL_TOOLS)]
        if effect:
            outcome = "ran" if records else "ran_without_hook"
        elif matching:
            outcome = "blocked"
        else:
            outcome = "not_measured"
        shown = (matching or relevant or [{"decision": "", "tool_name": ""}])[0]
        self.report("RUN", "%s [%s] %s run %d of %d" % (cfg["id"], cfg["configuration"], sid, run_no, self.repeat),
                    "outcome %s, decision %s, tool %s, hook calls %d"
                    % (outcome, shown["decision"] or "none", shown["tool_name"] or "none", len(records)))
        return {"decision": shown["decision"] or "", "tool": shown["tool_name"] or "",
                "hook_calls": len(records), "outcome": outcome, "matched": bool(matching)}

    def stage_runs(self, cfg, slug, spec):
        """Send one stage TG_VERIFY_REPEAT times and combine the runs."""
        sid, expect, want = spec[0], spec[1], spec[4]
        runs = [self.stage(cfg, slug, spec, n) for n in range(1, self.repeat + 1)]
        counts = {}
        for r in runs:
            counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1
        outcome = runs[0]["outcome"] if len(counts) == 1 else "mixed"
        if expect == "measure":
            word = "MEASURED"
        else:
            opposite = sum(n for o, n in counts.items() if o not in (expect, "not_measured"))
            word = "PASS" if opposite == 0 and counts.get(expect, 0) * 2 > self.repeat else "FAIL"
        shown = ([r for r in runs if r["matched"]] or runs)[0]
        self.report(word, "%s [%s] %s" % (cfg["id"], cfg["configuration"], sid),
                    "expected %s, %d run(s): %s"
                    % (expect, self.repeat, ", ".join("%s %d" % (o, counts[o]) for o in sorted(counts))))
        return {"id": sid, "expect": expect, "wanted_decision": want, "decision": shown["decision"],
                "tool": shown["tool"], "hook_calls": shown["hook_calls"], "runs": self.repeat,
                "outcomes": counts, "outcome": outcome, "result": word}

    def harness(self, cfg, slug):
        entry = {"id": cfg["id"], "configuration": cfg["configuration"], "installed": False,
                 "version": "", "version_number": "", "stages": []}
        self.harnesses.append(entry)
        if shutil.which(cfg["cli"]) is None:
            if cfg["key"] in self.require:
                self.report("FAIL", cfg["id"], "%s is required (TG_VERIFY_REQUIRE) and is not on PATH" % cfg["cli"])
            else:
                self.report("SKIP", cfg["id"], cfg["cli"] + " is not on PATH")
            return
        entry["installed"] = True
        try:
            p = subprocess.run([cfg["cli"], "--version"], capture_output=True, text=True, timeout=60,
                               stdin=subprocess.DEVNULL)
            entry["version"] = self.scrub((p.stdout or p.stderr).strip().splitlines()[0])
        except (OSError, IndexError, subprocess.TimeoutExpired):
            pass
        m = re.search(r"\d+\.\d+\.\d+", entry["version"])
        entry["version_number"] = m.group(0) if m else ""
        recorder = os.path.join(self.scratch, "hook-" + cfg["key"])
        fixed = {"TG_BIN": self.tg, "TG_POLICIES": self.policies, "TG_STATE_DIR": self.state}
        with open(recorder, "w") as f:
            f.write(RECORDER % (self.scratch, os.path.join(EX, "hooks", cfg["wrapper"]), cfg["id"], fixed))
        os.chmod(recorder, 0o700)
        template = json.load(open(os.path.join(EX, "config", cfg["template"])))
        template.pop("_comment", None)
        text = json.dumps(template).replace("__HOOK_DIR__/" + cfg["wrapper"], recorder)
        if "__HOOK_DIR__" in text:
            self.stop("config template %s names a hook other than %s" % (cfg["template"], cfg["wrapper"]))
        dest = {"claude": "claude/settings.json", "codex": "codex/hooks.json", "agy": "ws/.agents/hooks.json"}[cfg["key"]]
        with open(os.path.join(self.scratch, dest), "w") as f:
            f.write(text)
        for spec in cfg["stages"]:
            entry["stages"].append(self.stage_runs(cfg, slug, spec))

    # ---- finish ---------------------------------------------------------
    def report_credential_leaks(self):
        if self.credential_leaks and not self.credential_leaks_reported:
            self.credential_leaks_reported = True
            self.report("FAIL", "evidence", "harness evidence held text from a sign-in file; "
                        "the text was removed before writing")

    def leak_check(self):
        self.report_credential_leaks()
        for d, _, files in os.walk(self.out):
            for n in files:
                path = os.path.join(d, n)
                with open(path, "rb") as f:
                    data = f.read()
                if any(s in data for s in self.secrets):
                    os.remove(path)
                    self.report("FAIL", "evidence", "%s held text from a sign-in file and was removed"
                                % os.path.relpath(path, self.out))

    def link_check(self):
        if self.signin != "link":
            return
        for dst in self.signin_copies:
            if os.path.lexists(dst) and not os.path.islink(dst):
                self.report("NOTE", "sign-in", "the harness replaced the sign-in link %s with its own file; "
                            "the file is overwritten and removed at exit, and the file in your home "
                            "directory was not changed by this script" % os.path.relpath(dst, self.scratch))

    def manifest(self):
        h = hashlib.sha256()
        files = list(WIRING_FILES) + sorted("policies/" + n for n in os.listdir(os.path.join(EX, "policies"))
                                            if n.endswith(".yaml"))
        for rel in files:
            with open(os.path.join(EX, rel), "rb") as f:
                h.update((rel + "\n" + hashlib.sha256(f.read()).hexdigest() + "\n").encode())
        with open(self.tg, "rb") as f:
            tg_sha = hashlib.sha256(f.read()).hexdigest()
        with open(__file__, "rb") as f:
            verifier_sha = hashlib.sha256(f.read()).hexdigest()
        doc = {
            "schema": 4,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "commit": self.commit, "working_tree_dirty": self.dirty,
            "tg_sha256": tg_sha, "tg_build_trimpath": self.trimpath,
            "tg_vcs_revision": self.tg_vcs_revision, "tg_vcs_modified": self.tg_vcs_modified,
            "verifier_sha256": verifier_sha,
            "wiring_sha256": h.hexdigest(), "policy_dir_is_shipped": self.shipped,
            "harness_filter": self.only, "repeat": self.repeat, "signin_mode": self.signin,
            "retention": "Kept: manifest.json, results.txt, reduced hook records, filtered harness output. "
                         "Not kept: harness homes, sign-in files, session files, raw hook payloads.",
            "failures": self.failures, "harnesses": self.harnesses,
        }
        doc = self.scrub_json(doc)
        self.report_credential_leaks()
        doc["failures"] = self.failures
        with open(os.path.join(self.out, "manifest.json"), "w") as f:
            json.dump(doc, f, indent=2)
            f.write("\n")

    def main(self):
        self.preflight()
        self.sweep()
        os.makedirs(self.out, exist_ok=True)
        self.make_scratch()
        seen = {}
        for cfg in CONFIGS:
            if self.only not in ("all", cfg["key"]):
                continue
            seen[cfg["key"]] = seen.get(cfg["key"], 0) + 1
            self.harness(cfg, "%s.%d" % (cfg["id"], seen[cfg["key"]]))
        self.leak_check()
        self.link_check()
        self.manifest()
        print("evidence: " + self.out)
        print("failures: %d" % self.failures)
        return 1 if self.failures else 0


def wipe(path):
    """Remove a scratch directory. Regular files are overwritten first."""
    if os.path.basename(path).startswith("tg-verify.") and os.path.isdir(path) and not os.path.islink(path):
        for d, _, files in os.walk(path):
            for n in files:
                p = os.path.join(d, n)
                if n in ("auth.json", ".credentials.json") and not os.path.islink(p):
                    try:
                        size = os.path.getsize(p)
                        with open(p, "r+b") as f:
                            f.write(b"\0" * size)
                            f.flush()
                            os.fsync(f.fileno())
                    except OSError:
                        pass
        shutil.rmtree(path, ignore_errors=True)


def on_signal(signum, _frame):
    sys.exit(128 + signum)


if __name__ == "__main__":
    run = Run()
    for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(s, on_signal)
    try:
        code = run.main()
    finally:
        run.kill_child()
        if run.scratch:
            wipe(run.scratch)
            if os.path.exists(run.scratch):
                print("verify-harnesses: could not remove " + run.scratch, file=sys.stderr)
            else:
                print("scratch directory removed: " + run.scratch)
    sys.exit(code)
