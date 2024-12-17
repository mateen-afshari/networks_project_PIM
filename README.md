# **PIMbench Suite: Telemetry Benchmarks**

This repository is a fork of **PIMbench**, a comprehensive benchmark suite designed to evaluate Processing-In-Memory (PIM) systems. This repository adds several new **telemetry benchmarks** within the suite, providing tools to evaluate PIM architectures for network telemetry tasks like filtering, packet counting, round trip time, and jitter.

---

## **Description**

The **PIMbench Telemetry Benchmarks** include applications that are critical for network telemetry, such as:

- **Packet Filtering**: Efficient packet filtering based on a specific condition.
- **Packet Counting**: Counting packets for total traffic measurement.
- **Round Trip Time (RTT)**: Measuring the RTT for flows or devices.
- **Jitter**: Calculating variations in packet arrival times to assess network performance.

These benchmarks utilize the **PIMeval** package and api to implement and compute performance under PIM architectures.

---

## **Quick Start**

To run the telemetry benchmarks:

```bash
git clone <url_to_repository>
cd PIMeval-PIMbench/
make -j$(nproc)
cd PIMbench/telemetry-bench/<benchmark_folder>/PIM
make
./<application_executable_name>.out <args>
```

## **Telemetry Benchmarks**

The following benchmarks are included in the **Telemetry Bench** folder:

### **1. Filtering**

- **Description**: Filters packets based on a user-defined packet size threshold.
- **Command**:
  ```bash
  ./filter.out -p <pcap_file> -k <key_value>
  ```

### **2. Packet Counting**

- **Description**: Counts the number of packets in the included PCAP.
- **Command**:
  ```bash
  ./packet-count.out
  ```

### **3. Round Trip Time (RTT)**

- **Description**: Calculates the Round Trip Time (RTT) for packets in a flow.
- **Command**:
  ```bash
  ./RTT.out <pcap_file>
  ```

### **4. Jitter**

- **Description**: Computes the variation in packet arrival times (jitter).
- **Command**:
  ```bash
  ./jitter.out <pcap_file>
  ```

## Code Structure

```graphql
PIMeval-PIMbench/
├── telemetry-bench/                   # PIM benchmark suite
│   ├── packet-filtering/              # Filtering benchmark
│   │   ├── PIM/                       # PIM implementation
│   │   └── CPU/                       # CPU baseline
│   ├── packet-counting/               # Packet counting benchmark
│   │   └── PIM/                       # PIM implementation
│   ├── RTT/                           # Round Trip Time (RTT) benchmark
│   │   └── PIM/                       # PIM implementation
│   ├── Jitter/                        # Jitter calculation benchmark
│   │   └── PIM/                       # PIM implementation
```
