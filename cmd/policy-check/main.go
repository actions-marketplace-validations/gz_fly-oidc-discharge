// Command policy-check parses a policy file and exits non-zero if it is
// invalid. It reports advisory warnings but does not read any shared secret,
// so it runs in CI without credentials.
//
// Names come from the policy file and are printed quoted, so a stray control
// character cannot forge a line of output.
package main

import (
	"fmt"
	"os"

	"github.com/gz/fly-oidc-discharge/internal/policy"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: policy-check <policy.yaml>")
		os.Exit(2)
	}
	pol, err := policy.Load(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("%q: %d credentials\n", os.Args[1], len(pol.Credentials))
	for _, credential := range pol.Credentials {
		fmt.Printf("  %q (ttl %s)\n", credential.Name, credential.TTL(pol.DefaultDischargeTTL))
		for _, rule := range credential.Rules {
			fmt.Printf("    %q\n", rule.Name)
		}
	}
	for _, warning := range pol.Warnings() {
		fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
	}
}
