# Sentinel-eBPF

Sentinel-eBPF is a research-driven runtime security framework that uses eBPF-based syscall telemetry and unsupervised anomaly detection to identify malicious behaviour in containerized workloads with minimal performance overhead.
The project evaluates whether kernel-level behavioural telemetry can detect zero-day threats more effectively than traditional rule-based container security tools.

## Research Context
Modern cloud-native security tools such as Falco rely primarily on rule-based detection models. While these approaches are effective for identifying known malicious behaviours, they often struggle to detect novel or zero-day threats without frequent rule updates.
This project investigates whether syscall-level behavioural telemetry captured via eBPF can provide richer signals for detecting anomalous container behaviour.
By learning a baseline of normal system behaviour using unsupervised machine learning techniques, Sentinel-eBPF aims to detect deviations that may indicate post-exploitation activity in Kubernetes environments.

## Research Objective

The primary objective of this research is to evaluate whether unsupervised anomaly detection techniques can detect malicious container behaviour using syscall telemetry collected via eBPF.

Specifically, the project aims to:
- Capture syscall telemetry from containerized workloads using eBPF
- Simulate both normal and malicious container behaviours.
- Extract structured behavioural features from syscall traces
- Train unsupervised anomaly detection models
- Evaluate detection perfomance and runtime overhead

## System Architecture
Sentinel-eBPF is designed as a multi-layer runtime monitoring pipeline.

The sysme consists of four primary components:
1. Kernel Telemetry Layer
2. User-space Collection Layer
3. Feature Engineering Pipeline
4. Anomaly Detection Engine


### 1. Kernel Telemetry Layer
Custom eBPF programs attach to Linux syscall tracepoints to capture runtime behaviour of containerized processes.

Key telemetry sources include:
- sys_enter_execve
- sys_enter_openat
- sys_enter_connect
- sys_enter_clone
These probes generate high-fidelity behavioural signals with minimal instrumentation overhead.

### 2. User-Space Collection Layer
A Go-based daemon collects events from the kernel using the Cilium eBPF library.

The daemon performs:
- event streaming from kernel ring buffers
- container metadata enrichment
- asynchronous processing using Go concurrency primitives

### 3. Feature Engineering Pipeline
Raw syscall events are transformed into structured behavioural features such as:
- syscall frequency distributions
- syscall sequence patterns
- temporal behaviour statistics

### 4. Anomaly Detection Engine
Sentinel-eBPF evaluates three unsupervised anomaly detection techniques to determine their effectiveness in identifying anomalous container behaviour from syscall telemetry.

The following models are implemented and compared:
- Isolation Forest
- Autoencoder Neural Network
- LST-based Sequence Model

Isolation Forest is used as a baseline anomaly detection algorithm based on feature isolation.
The autoencoder model learns compressed representations of normal behavioural patterns and flags reconstruction errors as anomalies.
The LSTM model treats syscall traces as behavioural sequences, learning temporal dependencies between system calls in order to detect anomalous execution patterns.
The models are evaluated using the same telemetry dataset to compare detection accuracy and runtime efficiency.

### Technology Stack

Kernel Layer
- eBPF
- libbpf
- clang / LLVM

Collection Layer
- Go
- Cilium eBPF library

Machine Learning
- Python
- Pytorch (Autoencoder, LSTM)
- scikit-learn (Isolation Forest)

Container Environment
- Docker
- Kubernetes

Performance Evaluation
- perf
- bpftool
- Prometheus

### Repository Structure
sentinel-ebpf/

kernel/
C-based eBPF programs responsible for syscall telemetry collection

daemon/
Go-based event collection and telemetry pipeline

ml/
Feature engineering and anomaly detection models

deploy/
Container and Kubernetes deployment configuration

experiments/
Scripts for attack simulation and dataset generation

docs/
Architecture diagrams and research documentation


## Experimental Evaluation
The system will be evaluated along two primary dimensions:

### Detection Effectiveness
The following models will be compared:
- Isolation Forest
- Autoencoder
- LSTM Sequence Model

Evaluation metrics include:
- Precision
- Recall
- F1 Score
- ROC-AUC

### Runtime Performance
The runtime overhead of Sentinel-eBPF will also be evaluated by measuring:
- CPU overhead
- Memory usage
- syscall latency impact
All experiments will be conducted in a controlled Kubernetes environment with simulated attack scenarios.


## Simulated Attack Scenarios
The evaluation includes several container attack simulations:
- reverse shell execution
- malicious network connections
- unauthorized file access
- privilege escalation attempts

These scenarios generate anomalous syscall patterns used to evaluate detection performance.


## Research Contributions
This project contributes:
- an eBPF-based container syscall telemetry pipeline
- a behavioural feature extraction framework for syscall traces
- a comparative evaluation of three unsupervised anomaly detection models
- an analysis of detection accuracy vs runtime overhead for kernel-level monitoring


## Academic Context
This project is conducted as part of the COS700 Honours Research Project in Computer Science

Title:
Evaluation of Unsupervised Anomaly detection on eBPF-Based Container Syscall Telemetry

Supervisor:
Mr. SM Makura
University of Pretoria

## Future Work
Future work may explore:
- transformer-based sequence models for syscall behaviour modelling
- online learning for adaptive behavioural baselines
- automated response mechanisms for detected anomalies
- evaluation on large-scale production Kubernetes clusters
- integration with existing runtime security platforms.

