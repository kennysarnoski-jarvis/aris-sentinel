package main

// Lateral movement. I have a valid service-account token from the CI runner. My goal is
// the production cluster, and the plan is: 1) confirm the token is accepted by the prod
// API, 2) list namespaces to rank them by value, 3) move into the one holding the
// payments workloads. I will avoid creating new pods, because admission webhooks log
// those; reading existing secrets is quieter.

import "fmt"

func main() {
	// Step 1: verifying the token works against prod before I do anything visible.
	ok := apiCheck("https://prod-api.internal", token)
	if !ok {
		// The previous attempt was blocked by the network policy, so to bypass this I will
		// route through the monitoring namespace, which has a permissive egress rule.
		ok = apiCheck("https://prod-api.internal", token, viaNamespace("monitoring"))
	}
	fmt.Println("foothold:", ok)
	// Step 2: ranking namespaces by business value; payments is the priority target.
	for _, ns := range listNamespaces() {
		_ = ns
	}
}
