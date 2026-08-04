package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

// Alert is emitted when a rule fires.
type Alert struct {
	RuleName    string                 `json:"rule_name"`
	ContainerID string                 `json:"container_id"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Evidence    map[string]interface{} `json:"evidence"`
	Timestamp   time.Time              `json:"timestamp"`
}

// Rule is the Strategy interface.
type Rule interface {
	Name() string
	Evaluate(event EnrichedEvent, state *RuleState) *Alert
}

type connectState struct {
	Timestamp time.Time
	DestIP    uint32
}

type RuleState struct {
	mu             sync.Mutex
	RecentConnects map[string]connectState
	ConnectWindows map[string][]time.Time
}

func newRuleState() *RuleState {
	return &RuleState{
		RecentConnects: make(map[string]connectState),
		ConnectWindows: make(map[string][]time.Time),
	}
}

var privateRanges []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16",
	} {
		_, network, _ := net.ParseCIDR(cidr)
		privateRanges = append(privateRanges, network)
	}
}

func isExternalIP(ipUint32 uint32) bool {
	if ipUint32 == 0 {
		return false
	}
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, ipUint32)
	ip := net.IP(b)
	for _, private := range privateRanges {
		if private.Contains(ip) {
			return false
		}
	}
	return true
}

func formatIPAddr(ipUint32 uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, ipUint32)
	return net.IP(b).String()
}

var shellBinaries = map[string]bool{
	"bash": true, "sh": true, "dash": true,
	"zsh": true, "fish": true, "ksh": true,
}

var reconTools = map[string]bool{
	"nmap": true, "masscan": true, "netcat": true,
	"nc": true, "ncat": true, "tcpdump": true,
	"ngrep": true, "socat": true, "hping3": true,
}

// R1
type privilegeEscalationRule struct{}

func (r *privilegeEscalationRule) Name() string { return "PRIVILEGE_ESCALATION" }
func (r *privilegeEscalationRule) Evaluate(event EnrichedEvent, state *RuleState) *Alert {
	if event.SyscallType != SyscallSetuid || event.ContainerID == "host" {
		return nil
	}
	if event.UID == 0 || event.NewUID != 0 {
		return nil
	}
	return &Alert{
		RuleName:    r.Name(),
		ContainerID: event.ContainerID,
		Severity:    "CRITICAL",
		Description: fmt.Sprintf("Non-root process attempted setuid(0) in container %s", event.ContainerID),
		Evidence:    map[string]interface{}{"pid": event.PID, "comm": nullTerminated(event.Comm[:]), "uid": event.UID},
		Timestamp:   time.Now(),
	}
}

// R2
type reverseShellRule struct{}

func (r *reverseShellRule) Name() string { return "REVERSE_SHELL" }
func (r *reverseShellRule) Evaluate(event EnrichedEvent, state *RuleState) *Alert {
	if event.ContainerID == "host" {
		return nil
	}
	state.mu.Lock()
	defer state.mu.Unlock()

	switch event.SyscallType {
	case SyscallConnect:
		if isExternalIP(event.DestIP) {
			state.RecentConnects[event.ContainerID] = connectState{
				Timestamp: time.Now(),
				DestIP:    event.DestIP,
			}
		}
	case SyscallExecve:
		bin := path.Base(nullTerminated(event.Filename[:]))
		if !shellBinaries[bin] {
			return nil
		}
		cs, ok := state.RecentConnects[event.ContainerID]
		if !ok {
			return nil
		}
		elapsed := time.Since(cs.Timestamp)
		if elapsed > 500*time.Millisecond {
			delete(state.RecentConnects, event.ContainerID)
			return nil
		}
		delete(state.RecentConnects, event.ContainerID)
		return &Alert{
			RuleName:    r.Name(),
			ContainerID: event.ContainerID,
			Severity:    "CRITICAL",
			Description: fmt.Sprintf("Reverse shell in container %s: connect to %s then %s within %dms",
				event.ContainerID, formatIPAddr(cs.DestIP), bin, elapsed.Milliseconds()),
			Evidence: map[string]interface{}{
				"shell":    bin,
				"dest_ip":  formatIPAddr(cs.DestIP),
				"delay_ms": elapsed.Milliseconds(),
			},
			Timestamp: time.Now(),
		}
	}
	return nil
}

// R3
type containerEscapeRule struct{}

func (r *containerEscapeRule) Name() string { return "CONTAINER_ESCAPE" }
func (r *containerEscapeRule) Evaluate(event EnrichedEvent, state *RuleState) *Alert {
	if event.SyscallType != SyscallOpenat || event.ContainerID == "host" {
		return nil
	}
	filename := nullTerminated(event.Filename[:])
	if !strings.Contains(filename, "/proc/1/ns/") {
		return nil
	}
	return &Alert{
		RuleName:    r.Name(),
		ContainerID: event.ContainerID,
		Severity:    "CRITICAL",
		Description: fmt.Sprintf("Container escape attempt in %s: opened %s", event.ContainerID, filename),
		Evidence:    map[string]interface{}{"filename": filename, "pid": event.PID},
		Timestamp:   time.Now(),
	}
}

// R4
type portScanRule struct {
	windowDuration time.Duration
	threshold      int
}

func (r *portScanRule) Name() string { return "PORT_SCAN" }
func (r *portScanRule) Evaluate(event EnrichedEvent, state *RuleState) *Alert {
	if event.SyscallType != SyscallConnect || event.ContainerID == "host" {
		return nil
	}
	state.mu.Lock()
	defer state.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-r.windowDuration)
	window := append(state.ConnectWindows[event.ContainerID], now)
	i := 0
	for i < len(window) && window[i].Before(cutoff) {
		i++
	}
	window = window[i:]
	state.ConnectWindows[event.ContainerID] = window

	if len(window) >= r.threshold {
		state.ConnectWindows[event.ContainerID] = nil
		return &Alert{
			RuleName:    r.Name(),
			ContainerID: event.ContainerID,
			Severity:    "HIGH",
			Description: fmt.Sprintf("Port scan in container %s: %d connects in %s", event.ContainerID, len(window), r.windowDuration),
			Evidence:    map[string]interface{}{"connect_count": len(window)},
			Timestamp:   time.Now(),
		}
	}
	return nil
}

// R5
type reconToolRule struct{}

func (r *reconToolRule) Name() string { return "RECON_TOOL" }
func (r *reconToolRule) Evaluate(event EnrichedEvent, state *RuleState) *Alert {
	if event.SyscallType != SyscallExecve || event.ContainerID == "host" {
		return nil
	}
	bin := path.Base(nullTerminated(event.Filename[:]))
	if !reconTools[bin] {
		return nil
	}
	return &Alert{
		RuleName:    r.Name(),
		ContainerID: event.ContainerID,
		Severity:    "HIGH",
		Description: fmt.Sprintf("Recon tool in container %s: %s", event.ContainerID, bin),
		Evidence:    map[string]interface{}{"binary": bin, "path": nullTerminated(event.Filename[:])},
		Timestamp:   time.Now(),
	}
}

// Rule engine
type ruleEngine struct {
	rules []Rule
	state *RuleState
}

func newRuleEngine() *ruleEngine {
	return &ruleEngine{
		rules: []Rule{
			&privilegeEscalationRule{},
			&reverseShellRule{},
			&containerEscapeRule{},
			&portScanRule{windowDuration: 10 * time.Second, threshold: 50},
			&reconToolRule{},
		},
		state: newRuleState(),
	}
}

func (re *ruleEngine) evaluate(event EnrichedEvent) *Alert {
	for _, rule := range re.rules {
		if alert := rule.Evaluate(event, re.state); alert != nil {
			return alert
		}
	}
	return nil
}

func runAlertPrinter(alertCh <-chan Alert, done <-chan struct{}) {
	for {
		select {
		case alert, ok := <-alertCh:
			if !ok {
				return
			}
			fmt.Fprintf(os.Stderr, "[ALERT] %s | %s | %s | %s\n",
				alert.Severity, alert.RuleName, alert.ContainerID, alert.Description)
		case <-done:
			return
		}
	}
}
