# SDN Network Telemetry and Traffic Anomaly Detection

## About the Project

This project uses Software-Defined Networking (SDN) to monitor network traffic, detect suspicious activity, and automatically block malicious sources.

It uses Mininet to create a virtual network, Open vSwitch (OVS) to forward traffic, and the Ryu Controller to monitor network flows and manage traffic.

### Main Features

- Virtual network topology with hosts, switches, and routers.
- Reactive packet forwarding.
- Network flow statistics collection.
- Traffic feature extraction.
- Port scan and SYN-heavy traffic detection.
- Automatic blocking of suspicious IP addresses.
- CSV logging of network features and detected alerts.
- Packet capture for traffic analysis.

## Requirements

The project was developed and tested on Ubuntu 22.04.

Install the required tools:

```bash
sudo apt update
sudo apt install git python3 python3-venv python3-pip mininet openvswitch-switch iperf3 nmap hping3 curl tcpdump -y
```

## 1. Clone the Repository

```bash
git clone https://github.com/Asadahmed09/SDN-Traffic-Anomaly-Detection.git
cd SDN-Traffic-Anomaly-Detection
```

## 2. Set Up Ryu

Create a Python virtual environment and install Ryu:

```bash
python3 -m venv ~/ryu-env
source ~/ryu-env/bin/activate
pip install ryu==4.34
```

## 3. Start the Ryu Controller

Open the first terminal:

```bash
cd SDN-Traffic-Anomaly-Detection
source ~/ryu-env/bin/activate
export PYTHONPATH="$PWD:$PYTHONPATH"
ryu-manager controller.mitigation_switch
```

Keep this terminal running.

## 4. Start the Network Topology

Open a second terminal:

```bash
cd SDN-Traffic-Anomaly-Detection
sudo python3 run.py
```

Wait for Mininet to create the network and connect its switches to the controller.

## 5. Verify That the Project Is Working

Inside the Mininet terminal, run:

**Check network nodes:**

```bash
dump
```

**Test communication between hosts:**

```bash
h1 ping -c 4 10.0.2.10
```

Successful replies indicate that communication between the two networks is working.

**Generate normal HTTP traffic:**

Start the HTTP server:

```bash
h3 python3 -m http.server 80 &
```

Send an HTTP request:

```bash
h1 curl http://10.0.2.10
```

You should receive an HTTP directory listing.

**Test anomaly detection and mitigation:**

Generate a port scan from h2:

```bash
h2 nmap -sS -p 1-100 10.0.2.10
```

Check the Ryu controller terminal for a port-scan alert and blocking message.

After detection, test the suspicious host:

```bash
h2 ping -c 4 10.0.2.10
```

The suspicious source should be blocked temporarily.

Test the normal host:

```bash
h1 ping -c 4 10.0.2.10
```

The normal host should still be able to communicate.

## 6. Check Generated Logs

The project stores monitoring and detection results in CSV files.

```bash
ls -lh ~/sdn_logs
```

The main files are:

- `features.csv` – collected network flow statistics and extracted features.
- `alerts.csv` – detected anomalies and mitigation actions.

## 7. Stop the Project

Exit Mininet:

```bash
exit
```

Stop the Ryu controller by pressing `Ctrl + C` in the first terminal.

---

**Note:** Run the controller and Mininet in separate terminals. Keep the controller running while using the network.
