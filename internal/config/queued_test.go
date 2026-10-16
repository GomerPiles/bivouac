package config

import "testing"

func TestQueuedDemandRequiresExplicitScopeAndNoWarmPool(t *testing.T) {
	c, err := Parse([]byte(Example))
	if err != nil {
		t.Fatal(err)
	}
	c.GitHub.Demand = DemandQueued
	c.GitHub.QueueRepositories = []string{"example-org/repo"}
	p := c.Providers["macos"]
	p.IdlePool = 0
	c.Providers["macos"] = p
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, repos := range [][]string{nil, {"another-org/repo"}, {"example-org/repo", "EXAMPLE-ORG/REPO"}, {"example-org/../repo"}, {"example-org/.."}, {"example-org/"}} {
		c.GitHub.QueueRepositories = repos
		if err := c.Validate(); err == nil {
			t.Fatalf("accepted invalid queued scope: %v", repos)
		}
	}
	c.GitHub.QueueRepositories = []string{"example-org/repo"}
	p.IdlePool = 1
	c.Providers["macos"] = p
	if err := c.Validate(); err == nil {
		t.Fatal("queued demand accepted a warm pool")
	}
}
