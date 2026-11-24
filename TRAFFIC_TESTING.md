# Traffic Testing Guide

This file contains the traffic-generation commands used to test the SDN Network Telemetry and Traffic Anomaly Detection project.

Run these commands from the **Mininet CLI** after starting the project network. They provide repeatable examples for normal traffic and traffic that may be considered suspicious.

## 1. Before generating traffic

Start the Ryu controller in one Ubuntu terminal:

```bash
cd ~/SDN-Traffic-Anomaly-Detection-github
source ~/ryu-env/bin/activate
export PYTHONPATH="$PWD:$PYTHONPATH"
ryu-manager controller.learning_switch
```

Start the Mininet network in a second Ubuntu terminal:

```bash
cd ~/SDN-Traffic-Anomaly-Detection-github
sudo python3 run.py
```

The commands below are entered at the `mininet>` prompt.

**Network addresses used in these examples:**

- `h1`: `10.0.1.11` — normal traffic source
- `h2`: `10.0.1.66` — test traffic source
- `h3`: `10.0.2.10` — destination server

## 2. Normal traffic

### A. ICMP ping — connectivity test

```bash
h1 ping -c 10 10.0.2.10
```

**Purpose:** Checks whether h1 can reach h3 and shows basic delay and packet loss.

### B. HTTP — web request traffic

First, start an HTTP server on h3:

```bash
h3 python3 -m http.server 80 >/tmp/http.log 2>&1 &
```

Then send a request from h1:

```bash
h1 curl http://10.0.2.10
```

**Purpose:** Generates ordinary client-to-server HTTP traffic.

### C. iperf3 — sustained traffic

Start the iperf3 server on h3:

```bash
h3 iperf3 -s -D
```

Run a 10-second client test from h1:

```bash
h1 iperf3 -c 10.0.2.10 -t 10
```

**Purpose:** Generates sustained traffic and reports measured throughput.

## 3. Suspicious-pattern test traffic

These are controlled lab tests. They generate patterns that the detection module can examine; running a command does not guarantee that the system will classify or detect it.

### D. Nmap — port scan

Run a scan from h2:

```bash
h2 nmap -sS -p 1-100 10.0.2.10
```

**Purpose:** Sends probes to multiple destination ports. This can be used to test the project's port-scan detection logic.

### E. hping3 — repeated TCP SYN packets

Send a bounded set of 600 SYN packets from h2 to port 80 on h3:

```bash
h2 hping3 -S -p 80 -c 600 -i u1000 10.0.2.10
```

**Purpose:** Generates repeated TCP SYN packets to one destination port. This can be used to test the project's SYN-traffic detection logic.

**Note:** This is a limited lab test, not proof of a successful denial-of-service attack or of meeting the project's packets-per-second threshold.

## 4. Expected test categories

| Test | Expected category | What the monitoring module can examine |
|---|---|---|
| ICMP ping | Normal | Packet and byte counts |
| HTTP | Normal | Flow activity and traffic volume |
| iperf3 | Normal | Packet rate, byte rate and throughput |
| Nmap | Potential port scan | Number of distinct destination ports |
| hping3 | Potential SYN-heavy traffic | SYN packet rate and packet sizes |

The final classification depends on the thresholds and logic implemented by the detection module.

## 5. Suggested team testing workflow

1. Start the Ryu controller and Mininet topology.
2. Start the statistics-collection and detection modules.
3. Start any required server processes on h3.
4. Generate normal traffic first (ping, HTTP and iperf3).
5. Generate the Nmap and hping3 test traffic.
6. Check the statistics and detection output.
7. If mitigation is integrated, verify that suspicious traffic is handled while normal traffic remains functional.
8. Review the CSV logs and packet captures, if those modules are running.

## Notes

- Run these commands only in the project's authorised Mininet lab environment.
- The examples assume the IP addresses and host names in the project's current topology.
- Start the HTTP and iperf3 servers before running their client commands.
- Each team member can use these examples in their own local test environment. For a combined demonstration, all modules must be running against the **same Mininet network and switches**.
- These commands generate test traffic; they do not themselves collect statistics, detect anomalies, or apply mitigation.
