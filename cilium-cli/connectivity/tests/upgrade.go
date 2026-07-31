// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"bytes"
	"context"
	gojson "encoding/json"
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/k8s"
)

// NoInterruptedConnections checks whether there are no interruptions in
// long-lived E/W LB connections. The test case is used to validate Cilium
// upgrades.
//
// The test case consists of three steps:
//
// 1. Deploying pods and a service which establish the long-lived connections
// (done by "--conn-disrupt-test-setup"). The client pods ("test-conn-disrupt-client")
// establish connections via ClusterIP ("test-conn-disrupt") to server pods
// ("test-conn-disrupt-server"). As there former pods come first before the latter,
// the former pods can crash which increases the pod restart counter. The step
// is responsible for storing the restart counter too.
// 2. Do Cilium upgrade.
// 3. Run the test ("--include-conn-disrupt-test"). The test checks the restart
// counters, and compares them against the previously stored ones. A mismatch
// indicates that a connection was interrupted.
func NoInterruptedConnections() check.Scenario {
	return &noInterruptedConnections{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type noInterruptedConnections struct {
	check.ScenarioBase
}

func (n *noInterruptedConnections) Name() string {
	return "no-interrupted-connections"
}

func (n *noInterruptedConnections) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	restartCount := make(map[string]string)
	// podClients remembers which client a given pod was observed through, so
	// that a restart-count mismatch can be explained by querying the very same
	// pod for the reason its container restarted.
	podClients := make(map[string]*k8s.Client)
	for _, client := range ct.Clients() {
		if ct.Params().IncludeConnDisruptTest {
			pods, err := client.ListPods(ctx, ct.Params().TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + check.KindTestConnDisrupt})
			if err != nil {
				t.Fatalf("Unable to list test-conn-disrupt pods: %s", err)
			}
			if len(pods.Items) == 0 {
				t.Fatal("No test-conn-disrupt-{client,server} pods found")
			}

			for _, pod := range pods.Items {
				restartCount[pod.GetObjectMeta().GetName()] = strconv.Itoa(int(pod.Status.ContainerStatuses[0].RestartCount))
				podClients[pod.GetObjectMeta().GetName()] = client
			}
		}

		if ct.ShouldRunConnDisruptNSTraffic() {
			pods, err := client.ListPods(ctx, ct.Params().TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + check.KindTestConnDisruptNSTraffic})
			if err != nil {
				t.Fatalf("Unable to list test-conn-disrupt-ns-traffic pods: %s", err)
			}
			if len(pods.Items) == 0 {
				t.Fatal("No test-conn-disrupt-{client,server} for NS traffic pods found")
			}

			for _, pod := range pods.Items {
				restartCount[pod.GetObjectMeta().GetName()] = strconv.Itoa(int(pod.Status.ContainerStatuses[0].RestartCount))
				podClients[pod.GetObjectMeta().GetName()] = client
			}
		} else {
			ct.Info("Skipping conn-disrupt-test for NS traffic")
		}

		if ct.ShouldRunConnDisruptL7Traffic() {
			pods, err := client.ListPods(ctx, ct.Params().TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + check.KindTestConnDisruptL7Traffic})
			if err != nil {
				t.Fatalf("Unable to list test-conn-disrupt-l7-traffic pods: %s", err)
			}
			if len(pods.Items) == 0 {
				t.Fatal("No test-conn-disrupt-{client,server} for L7 traffic pods found")
			}

			for _, pod := range pods.Items {
				restartCount[pod.GetObjectMeta().GetName()] = strconv.Itoa(int(pod.Status.ContainerStatuses[0].RestartCount))
				podClients[pod.GetObjectMeta().GetName()] = client
			}
		} else {
			ct.Info("Skipping conn-disrupt-test for L7 traffic")
		}

		if ct.ShouldRunConnDisruptEgressGateway() {
			pods, err := client.ListPods(ctx, ct.Params().TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + check.KindTestConnDisruptEgressGateway})
			if err != nil {
				t.Fatalf("Unable to list test-conn-disrupt-egw pods: %s", err)
			}
			if len(pods.Items) == 0 {
				t.Fatal("No test-conn-disrupt-{client,server} for Egress Gateway pods found")
			}

			for _, pod := range pods.Items {
				restartCount[pod.GetObjectMeta().GetName()] = strconv.Itoa(int(pod.Status.ContainerStatuses[0].RestartCount))
				podClients[pod.GetObjectMeta().GetName()] = client
			}
		} else {
			ct.Info("Skipping conn-disrupt-test for Egress Gateway")
		}
	}

	// Only store restart counters which will be used later when running the same
	// test case, but w/o --conn-disrupt-test-setup.
	if ct.Params().ConnDisruptTestSetup {
		armEnvoyCloseLoggers(ctx, ct)

		file, err := os.Create(ct.Params().ConnDisruptTestRestartsPath)
		if err != nil {
			t.Fatalf("Failed to create %q file for writing conn disrupt test temp results: %s",
				ct.Params().ConnDisruptTestRestartsPath, err)
		}
		defer file.Close()

		counts := maps.Clone(restartCount)
		j, err := gojson.Marshal(counts)
		if err != nil {
			t.Fatalf("Failed to marshal JSON: %s", err)
		}

		if _, err := file.Write(j); err != nil {
			t.Fatalf("Failed to write conn disrupt test temp result into file: %s", err)
		}

		return
	}

	b, err := os.ReadFile(ct.Params().ConnDisruptTestRestartsPath)
	if err != nil {
		t.Fatalf("Failed to read conn disrupt test result files: %s", err)
	}
	prevRestartCount := make(map[string]string)
	if err := gojson.Unmarshal(b, &prevRestartCount); err != nil {
		t.Fatalf("Failed to unmarshal JSON test result file: %s", err)
	}

	for pod, count := range restartCount {
		if prevCount, found := prevRestartCount[pod]; !found {
			t.Fatalf("Could not find Pod %s restart count", pod)
		} else if prevCount != count {
			t.Fatalf("Pod %s flow was interrupted (restart count does not match %s != %s)%s%s",
				pod, prevCount, count, restartReason(ctx, ct, podClients[pod], pod),
				connDisruptPeerState(ctx, ct, podClients[pod]))
		}
	}
}

// connDisruptPeerState dumps the state of the conn-disrupt SERVER pods when a
// client restart is reported. WIP DO NOT MERGE: debug instrumentation.
//
// Why: an L7 conn-disrupt client dies because the server stops answering for
// several seconds (6.8s and 11.7s stalls observed), but every artifact we
// collect today describes the CLIENT. restartReason() reports the client's
// termination state and its own log tail, the server pod's application log is
// not collected at all, and the cilium-agent/cilium-envoy logs in the sysdump
// have already rotated past the stall by the time it is taken. So we can see
// that the server went quiet but not why.
func connDisruptPeerState(ctx context.Context, ct *check.ConnectivityTest, client *k8s.Client) string {
	if client == nil {
		return ""
	}

	pods, err := client.ListPods(ctx, ct.Params().TestNamespace, metav1.ListOptions{
		LabelSelector: "kind=" + check.KindTestConnDisruptL7Traffic,
	})
	if err != nil {
		return fmt.Sprintf("\n[peer-state] unable to list L7 conn-disrupt pods: %s", err)
	}

	var sb strings.Builder
	sb.WriteString("\n[peer-state] L7 conn-disrupt server pods at failure time:")
	for _, pod := range pods.Items {
		if !strings.HasPrefix(pod.Name, "test-conn-disrupt-server") {
			continue
		}

		var restarts int32
		var ready bool
		if len(pod.Status.ContainerStatuses) > 0 {
			restarts = pod.Status.ContainerStatuses[0].RestartCount
			ready = pod.Status.ContainerStatuses[0].Ready
		}
		fmt.Fprintf(&sb, "\n  %s node=%s phase=%s ready=%t restarts=%d",
			pod.Name, pod.Spec.NodeName, pod.Status.Phase, ready, restarts)

		// The server is a plain HTTP echo; if it logged nothing while the
		// client was timing out, the stall is below the application.
		var logs bytes.Buffer
		if err := client.GetLogs(ctx, pod.Namespace, pod.Name, pod.Spec.Containers[0].Name,
			corev1.PodLogOptions{TailLines: ptr.To[int64](30), Timestamps: true}, &logs); err == nil {
			if trimmed := strings.TrimSpace(logs.String()); trimmed != "" {
				fmt.Fprintf(&sb, "\n  --- %s log tail ---\n%s", pod.Name, trimmed)
			} else {
				fmt.Fprintf(&sb, "\n  --- %s produced no log output ---", pod.Name)
			}
		}

		sb.WriteString(envoyStallCounters(ctx, ct, pod.Spec.NodeName))
	}

	// The local close happens on the CLIENT's node, so collect the close
	// evidence and the per-node close counters for every node, not just the
	// server's.
	for _, cp := range ct.CiliumPods() {
		sb.WriteString(envoyLocalCloseCounters(ctx, ct, cp))
		sb.WriteString(envoyCloseEvidence(ctx, ct, cp.Pod.Spec.NodeName))
	}

	return sb.String()
}

// envoyLocalCloseCounters reports, per node, which local-close path Envoy took.
// WIP DO NOT MERGE. max_requests and max_duration_reached being 0 while
// destroy_local_with_active_rq is 1 is what narrows this to idle-timeout vs
// pool drain.
func envoyLocalCloseCounters(ctx context.Context, ct *check.ConnectivityTest, cp check.Pod) string {
	const filter = "upstream_cx_(destroy_local_with_active_rq|destroy_remote_with_active_rq|idle_timeout|max_requests|max_duration_reached|total)|upstream_rq_(total|completed|pending_overflow)"
	out, err := cp.K8sClient.ExecInPod(ctx, cp.Pod.Namespace, cp.Pod.Name, "cilium-agent",
		[]string{"bash", "-c", "cilium-dbg envoy admin metrics -f '" + filter +
			"' 2>/dev/null | grep -E 'egress-cluster\"|ingress-cluster\"' | grep -vE ' 0$'"})
	if err != nil {
		return fmt.Sprintf("\n  [close-counters] %s: %s", cp.Pod.Name, err)
	}
	return fmt.Sprintf("\n  --- local-close counters on %s (%s) ---\n%s",
		cp.Pod.Spec.NodeName, cp.Pod.Name, strings.TrimSpace(out.String()))
}

// armEnvoyCloseLoggers raises the Envoy loggers that name the upstream
// connection close, before the agent is restarted. WIP DO NOT MERGE.
//
// Why: the failing request dies because Envoy destroys its own upstream
// connection while the request is still active. Proven by
// upstream_cx_destroy_local_with_active_rq=1 (and _remote_=0) on exactly the
// nodes whose client restarted, 0 on the nodes whose client survived, across 9
// client samples in 3 runs with no exception. What the counters cannot say is
// WHICH local close path ran. upstream_cx_max_requests and
// upstream_cx_max_duration_reached are 0 everywhere, so it is either the 3s
// upstream idle timeout racing a request assignment or a connection-pool drain
// during restore, and both are cumulative so elimination is not proof.
//
// codec_client.h onIdleTimeout() logs "idle timeout" and conn_pool_base.cc
// drainConnectionsImpl() logs "draining" at debug on the connection/pool
// loggers, so raising just those two names says which one fired, without the
// ~1600 lines/s that --log-level trace produces and that has been rotating the
// evidence away.
func armEnvoyCloseLoggers(ctx context.Context, ct *check.ConnectivityTest) {
	if !ct.ShouldRunConnDisruptL7Traffic() {
		return
	}

	for _, cp := range ct.CiliumPods() {
		out, err := cp.K8sClient.ExecInPod(ctx, cp.Pod.Namespace, cp.Pod.Name, "cilium-agent",
			[]string{"cilium-dbg", "envoy", "admin", "logging", "set", "loggers",
				// router names the reset reason ("upstream reset: reset reason: ...",
				// router.cc:1206) and connection names the peer at connect time
				// ("connecting to {}", connection_impl.cc:923), keyed by the same
				// ConnectionId as the "remote close" line.
				"connection=debug", "pool=debug", "client=debug", "upstream=debug",
				"router=debug", "http=debug", "filter=debug"})
		if err != nil {
			ct.Infof("[close-probe] %s: unable to raise Envoy loggers: %s", cp.Pod.Name, err)
			continue
		}
		ct.Infof("[close-probe] %s: raised Envoy connection/pool loggers: %s",
			cp.Pod.Name, strings.TrimSpace(out.String()))
	}
}

// envoyCloseEvidence mines the Envoy log for the lines that describe the
// request that never got a response. WIP DO NOT MERGE.
//
// Reads the log FILE, not the container log. envoy.log.path makes Envoy write
// to /var/run/cilium/envoy/sockets/envoy.log on a hostPath that the agent also
// mounts, so it is not subject to kubelet's 10Mi stdout rotation. That rotation
// is why every previous attempt lost the window: with the debug loggers raised
// Envoy emits ~1000 lines/s, so the container log covered only the last ~70s
// and always started AFTER the client death.
func envoyCloseEvidence(ctx context.Context, ct *check.ConnectivityTest, nodeName string) string {
	if nodeName == "" {
		return ""
	}

	// Read the cilium-envoy CONTAINER log. An earlier revision redirected Envoy
	// to a file via envoy.log.path and read that instead; that was a mistake,
	// because it emptied the container log the sysdump collects (the sysdump for
	// run 30555072318 has 0 bytes of Envoy log on all three nodes) while the
	// file itself is not collected at all. With container-log-max-size raised,
	// the container log is both retained and archived, so use it.
	pods, err := ct.K8sClient().ListPods(ctx, ct.Params().CiliumNamespace, metav1.ListOptions{
		LabelSelector: "k8s-app=cilium-envoy",
		FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil || len(pods.Items) == 0 {
		return fmt.Sprintf("\n  [close-probe] no cilium-envoy pod on node %s (%v)", nodeName, err)
	}

	var logs bytes.Buffer
	if err := ct.K8sClient().GetLogs(ctx, pods.Items[0].Namespace, pods.Items[0].Name, "cilium-envoy",
		corev1.PodLogOptions{TailLines: ptr.To[int64](400000)}, &logs); err != nil {
		return fmt.Sprintf("\n  [close-probe] unable to read %s logs: %s", pods.Items[0].Name, err)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "\n  --- envoy close evidence on %s (%s, %d bytes) ---", nodeName, pods.Items[0].Name, logs.Len())

	// A previous run proved the killing event is "remote close" followed by
	// "disconnect. resetting 1 pending requests" - the PEER closed, not Envoy.
	// Keyword grepping cannot say which peer, because the address is only
	// logged at connect time on a separate line. So first find the ConnectionIds
	// that reset a pending request, then replay every line for those ids: that
	// pulls in "connecting to <addr>" (connection_impl.cc:923) and "upstream
	// reset: reset reason: ..." (router.cc:1206) for the same connection.
	connIDRe := regexp.MustCompile(`"ConnectionId":"(\d+)"`)
	lines := strings.Split(logs.String(), "\n")

	// Every reset found so far turned out to be the xDS socket, not the
	// conn-disrupt request: ConnectionId 21 / 5 were "connecting to
	// /var/run/cilium/envoy/sockets/xds.sock", their pending request was the ADS
	// gRPC stream, and they preceded the client death by 70-88s. That is normal
	// agent-restart churn. So build the set of ConnectionIds that are xDS (or
	// any other unix socket) and exclude them.
	xdsIDs := map[string]bool{}
	for _, line := range lines {
		if !strings.Contains(line, "connecting to") || !strings.Contains(line, ".sock") {
			continue
		}
		if m := connIDRe.FindStringSubmatch(line); m != nil {
			xdsIDs[m[1]] = true
		}
	}

	culprits := map[string]bool{}
	for _, line := range lines {
		if !strings.Contains(line, "resetting") || !strings.Contains(line, "pending request") {
			continue
		}
		if strings.Contains(line, "resetting 0 pending requests") {
			continue // benign teardown of an unused pooled connection
		}
		if m := connIDRe.FindStringSubmatch(line); m != nil {
			if xdsIDs[m[1]] {
				continue // xDS/unix-socket connection, not the conn-disrupt request
			}
			culprits[m[1]] = true
		}
	}
	if len(xdsIDs) > 0 {
		fmt.Fprintf(&sb, "\n    (excluded %d unix-socket/xDS ConnectionIds)", len(xdsIDs))
	}

	// The conn-disrupt request is HTTP over TCP to port 8000, so surface every
	// stream whose route/host mentions it, plus any non-xDS upstream reset.
	// This is the trail that matters and that no previous probe isolated.
	fmt.Fprintf(&sb, "\n    === port-8000 / non-xDS stream trail ===")
	var t int
	for _, line := range lines {
		if strings.Contains(line, ".sock") {
			continue
		}
		if !strings.Contains(line, ":8000") && !strings.Contains(line, "upstream reset") &&
			!strings.Contains(line, "/echo") {
			continue
		}
		fmt.Fprintf(&sb, "\n      %s", line)
		if t++; t >= 80 {
			sb.WriteString("\n      ... truncated")
			break
		}
	}
	if t == 0 {
		sb.WriteString("\n      (nothing found - the request may not have reached this node's Envoy)")
	}

	if len(culprits) == 0 {
		sb.WriteString("\n    (no connection reset a pending request in the retained log window)")
		return sb.String()
	}

	ids := slices.Sorted(maps.Keys(culprits))
	fmt.Fprintf(&sb, "\n    ConnectionIds that reset a pending request: %v", ids)
	for _, id := range ids {
		fmt.Fprintf(&sb, "\n    === full trail for ConnectionId %s ===", id)
		want := `"ConnectionId":"` + id + `"`
		var shown int
		for _, line := range lines {
			if !strings.Contains(line, want) {
				continue
			}
			fmt.Fprintf(&sb, "\n      %s", line)
			if shown++; shown >= 40 {
				sb.WriteString("\n      ... truncated")
				break
			}
		}
	}

	// The reset reason and the upstream host are logged without a ConnectionId
	// tag, so surface them separately.
	fmt.Fprintf(&sb, "\n    === reset reasons / upstream hosts (untagged lines) ===")
	var extra int
	for _, line := range lines {
		low := strings.ToLower(line)
		if strings.Contains(low, "upstream reset") || strings.Contains(low, "connecting to") ||
			strings.Contains(low, "transport failure reason") {
			fmt.Fprintf(&sb, "\n      %s", line)
			if extra++; extra >= 40 {
				sb.WriteString("\n      ... truncated")
				break
			}
		}
	}
	if extra == 0 {
		sb.WriteString("\n      (none found)")
	}

	return sb.String()
}

// envoyStallCounters dumps the Envoy counters that describe a stall on the
// node hosting the conn-disrupt server. WIP DO NOT MERGE: debug instrumentation.
//
// Why: these are cumulative and are served from the running cilium-envoy, so
// unlike the container logs they still cover the stall window when the sysdump
// is taken minutes later. upstream_cx_destroy_with_active_rq / _idle_timeout
// tell us whether Envoy tore the upstream connection down under an in-flight
// request, downstream_rq_idle_timeout whether the stream idle timer fired, and
// the watchdog counters whether the Envoy worker threads were descheduled.
func envoyStallCounters(ctx context.Context, ct *check.ConnectivityTest, nodeName string) string {
	if nodeName == "" {
		return ""
	}

	for _, cp := range ct.CiliumPods() {
		if cp.Pod.Spec.NodeName != nodeName {
			continue
		}

		// -f is applied by Envoy itself; the grep only drops the zero-valued
		// series so the failure message stays readable.
		const filter = "upstream_cx_(total|idle_timeout|destroy_with_active_rq|connect_fail)|downstream_rq_(idle_timeout|timeout|5xx)|watchdog_(miss|mega_miss)"
		out, err := cp.K8sClient.ExecInPod(ctx, cp.Pod.Namespace, cp.Pod.Name, "cilium-agent",
			[]string{"bash", "-c", "cilium-dbg envoy admin metrics -f '" + filter + "' 2>/dev/null | grep -vE ' 0$'"})
		if err != nil {
			return fmt.Sprintf("\n  [envoy-counters] %s: %s", cp.Pod.Name, err)
		}
		if trimmed := strings.TrimSpace(out.String()); trimmed != "" {
			return fmt.Sprintf("\n  --- envoy nonzero stall counters on %s (%s) ---\n%s",
				nodeName, cp.Pod.Name, trimmed)
		}
		return fmt.Sprintf("\n  [envoy-counters] %s: no matching nonzero counters", cp.Pod.Name)
	}

	return fmt.Sprintf("\n  [envoy-counters] no cilium pod found on node %s", nodeName)
}

// restartReason returns a human-readable, best-effort explanation of why the
// container of the given conn-disrupt client/server pod restarted. It reports
// the last termination state (exit code, signal, reason) and the tail of the
// previous container's logs. It is only used to enrich the failure message so
// that a benign environmental restart can be told apart from a genuine
// connection disruption; it never changes the pass/fail outcome and swallows
// its own errors, returning an empty string when nothing can be collected.
func restartReason(ctx context.Context, ct *check.ConnectivityTest, client *k8s.Client, podName string) string {
	if client == nil {
		return ""
	}

	pod, err := client.GetPod(ctx, ct.Params().TestNamespace, podName, metav1.GetOptions{})
	if err != nil || len(pod.Status.ContainerStatuses) == 0 {
		return ""
	}

	cs := pod.Status.ContainerStatuses[0]
	var sb strings.Builder
	if term := cs.LastTerminationState.Terminated; term != nil {
		fmt.Fprintf(&sb, "; last termination: exitCode=%d signal=%d reason=%q message=%q startedAt=%s finishedAt=%s",
			term.ExitCode, term.Signal, term.Reason, term.Message,
			term.StartedAt.Format(time.RFC3339), term.FinishedAt.Format(time.RFC3339))
	}

	var logs bytes.Buffer
	err = client.GetLogs(ctx, pod.Namespace, podName, cs.Name,
		corev1.PodLogOptions{Previous: true, TailLines: ptr.To[int64](20)}, &logs)
	if err == nil {
		if trimmed := strings.TrimSpace(logs.String()); trimmed != "" {
			fmt.Fprintf(&sb, "; previous container logs (tail):\n%s", trimmed)
		}
	}

	return sb.String()
}
