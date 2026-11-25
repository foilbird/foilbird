// SPDX-License-Identifier: Apache-2.0

// foil-k8s-env renders parts of the applied configuration into environment files for systemd units (the node has no
// shell, so this small, strict converter replaces "$(cat file)"):
//   - k8s.node-labels, k8s.node-taints -> /run/foilbird/kubelet.env   (KUBELET_EXTRA_ARGS for kubelet.service)
//   - k8s.join apiServerEndpoint     -> /run/foilbird/apiserver.env (FOILBIRD_APISERVER for the node-local API proxy)
// Values are validated against the Kubernetes syntax; anything else is rejected and kubelet is not started.
package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

const (
	configDir = "/run/foilbird/config"
	outFile   = "/run/foilbird/kubelet.env"
	apiFile   = "/run/foilbird/apiserver.env"
)

var (
	// qualified name: optional DNS-subdomain prefix + "/" + name (63 chars, alnum at both ends)
	keyRe   = regexp.MustCompile(`^([a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*/)?[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$`)
	valueRe = regexp.MustCompile(`^([A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?)?$`)
	// apiServerEndpoint: host (DNS name or IPv4) and port; IPv6 in brackets
	endpointRe = regexp.MustCompile(`^([A-Za-z0-9]([-A-Za-z0-9.]{0,251}[A-Za-z0-9])?|\[[0-9A-Fa-f:]+\]):[0-9]{1,5}$`)
	serverRe   = regexp.MustCompile(`(?m)^\s*server:\s*https://([^/\s]+)/?\s*$`)
	joinLineRe = regexp.MustCompile(`(?m)^\s*apiServerEndpoint:\s*"?([^"\s]+)"?\s*$`)
	effects    = map[string]bool{"NoSchedule": true, "PreferNoSchedule": true, "NoExecute": true}
)

func read(name string) (string, error) {
	b, err := os.ReadFile(configDir + "/" + name)
	if os.IsNotExist(err) {
		return "", nil
	}
	return strings.TrimSpace(string(b)), err
}

func split(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func labels(s string) (string, error) {
	items := split(s)
	for _, it := range items {
		k, v, ok := strings.Cut(it, "=")
		if !ok || !keyRe.MatchString(k) || !valueRe.MatchString(v) {
			return "", fmt.Errorf("bad label %q", it)
		}
	}
	sort.Strings(items)
	return strings.Join(items, ","), nil
}

func taints(s string) (string, error) {
	items := split(s)
	for _, it := range items {
		kv, eff, ok := strings.Cut(it, ":")
		if !ok || !effects[eff] {
			return "", fmt.Errorf("bad taint effect in %q", it)
		}
		k, v, _ := strings.Cut(kv, "=")
		if !keyRe.MatchString(k) || !valueRe.MatchString(v) {
			return "", fmt.Errorf("bad taint %q", it)
		}
	}
	return strings.Join(items, ","), nil
}

func writeFile(path, content string) error {
	if err := os.MkdirAll("/run/foilbird", 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// apiserver writes FOILBIRD_APISERVER from k8s.join or, once joined and without k8s.join, from kubelet's kubeconfig.
// Neither present = not joined = no proxy target (the proxy unit then fails to start, kubelet is unaffected).
func apiserver() error {
	j, err := read("k8s.join")
	if err != nil {
		return err
	}
	re, src := joinLineRe, "k8s.join"
	if j == "" {
		b, err := os.ReadFile("/etc/kubernetes/kubelet.conf")
		if os.IsNotExist(err) {
			return nil
		} else if err != nil {
			return err
		}
		j, re, src = string(b), serverRe, "/etc/kubernetes/kubelet.conf"
	}
	m := re.FindAllStringSubmatch(j, -1)
	if len(m) != 1 || !endpointRe.MatchString(m[0][1]) {
		return fmt.Errorf("%s: expected exactly one valid API server endpoint", src)
	}
	line := "FOILBIRD_APISERVER=" + m[0][1] + "\n"
	fmt.Print(line)
	return writeFile(apiFile, line)
}

func run() error {
	l, err := read("k8s.node-labels")
	if err != nil {
		return err
	}
	t, err := read("k8s.node-taints")
	if err != nil {
		return err
	}
	if l, err = labels(l); err != nil {
		return err
	}
	if t, err = taints(t); err != nil {
		return err
	}
	var args []string
	if l != "" {
		args = append(args, "--node-labels="+l)
	}
	if t != "" {
		args = append(args, "--register-with-taints="+t)
	}
	line := "KUBELET_EXTRA_ARGS=" + strings.Join(args, " ") + "\n"
	if err := writeFile(outFile, line); err != nil {
		return err
	}
	fmt.Print(line)
	return apiserver()
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "foil-k8s-env:", err)
		os.Exit(1)
	}
}
