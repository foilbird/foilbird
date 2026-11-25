// SPDX-License-Identifier: Apache-2.0
package main

import "testing"

func TestLabels(t *testing.T) {
	good := map[string]string{
		"":                                  "",
		"pool=testing,foilbird.com/profile=k8s-worker": "foilbird.com/profile=k8s-worker,pool=testing",
		"a=":                                "a=",
	}
	for in, want := range good {
		if got, err := labels(in); err != nil || got != want {
			t.Errorf("labels(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"a", "a=b c", "a=$(x)", "-a=b", "a=b,,c=d", "a=b --x=y"} {
		if _, err := labels(in); err == nil {
			t.Errorf("labels(%q): want error", in)
		}
	}
}

func TestTaints(t *testing.T) {
	if got, err := taints("pool=testing:NoSchedule,gpu:NoExecute"); err != nil || got != "pool=testing:NoSchedule,gpu:NoExecute" {
		t.Errorf("taints: %q %v", got, err)
	}
	for _, in := range []string{"pool=testing", "pool=testing:Bogus", "p o:NoSchedule", "a=b:NoSchedule c"} {
		if _, err := taints(in); err == nil {
			t.Errorf("taints(%q): want error", in)
		}
	}
}

func TestEndpoint(t *testing.T) {
	j := "discovery:\n  bootstrapToken:\n    apiServerEndpoint: 192.0.2.20:6443\n"
	m := joinLineRe.FindAllStringSubmatch(j, -1)
	if len(m) != 1 || m[0][1] != "192.0.2.20:6443" || !endpointRe.MatchString(m[0][1]) {
		t.Fatalf("join endpoint: %v", m)
	}
	k := "clusters:\n- cluster:\n    server: https://api.example:6443\n"
	if m := serverRe.FindAllStringSubmatch(k, -1); len(m) != 1 || m[0][1] != "api.example:6443" {
		t.Fatalf("kubeconfig server: %v", m)
	}
	for _, bad := range []string{"192.0.2.20", "a;b:1", "x:6443 --flag", ""} {
		if endpointRe.MatchString(bad) {
			t.Errorf("endpoint %q accepted", bad)
		}
	}
}
