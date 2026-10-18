package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"strings"
)

type auditVerificationFlags struct {
	allowPruned    bool
	checkpointHash string
}

func addAuditVerificationFlags(fs *flag.FlagSet) *auditVerificationFlags {
	options := &auditVerificationFlags{}
	fs.BoolVar(&options.allowPruned, "allow-pruned", false, "accept an unsigned prune checkpoint; verify internal consistency only")
	fs.Func("checkpoint-hash", "require a checkpoint matching sha256:<64 lowercase hex>; implies -allow-pruned", func(value string) error {
		digest, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
		if err != nil || len(digest) != 32 || value != "sha256:"+hex.EncodeToString(digest) {
			return fmt.Errorf("checkpoint hash must be sha256:<64 lowercase hex>")
		}
		options.checkpointHash = value
		return nil
	})
	return options
}
