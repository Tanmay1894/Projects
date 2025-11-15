**CyberSleuth: Unified Cybersecurity Detection System**

Network Anomaly Detection | Web Vulnerability Scanning | Phishing URL Classification

CyberSleuth is an integrated cybersecurity analysis platform that merges network traffic monitoring, web vulnerability scanning, and phishing URL classification into one unified system.
A central Correlation Engine intelligently links results from all three modules to identify multi-vector attacks, reduce false positives, and improve threat accuracy.

The backend is built in Python, and the frontend features a React.js dashboard for real-time visualization and reporting.

**🚀 Key Modules
1️⃣ Network Packet Analyzer & ML-Based Anomaly Detection**

Captures live packets using Scapy.

Extracts network features (IP, ports, protocol flags, payload statistics).

Uses ML algorithms such as Random Forest.

Detects network threats including:

Botnet activity

Port scans

DDoS-like patterns

Data exfiltration

Suspicious outbound connections

**2️⃣ Automated Web Vulnerability Scanner**

Crawls website endpoints automatically.

Injects crafted payloads to test for vulnerabilities:

SQL Injection (SQLi)

Cross-Site Scripting (XSS)

Cross-Site Request Forgery (CSRF)

Open Redirects

Directory Traversal

Produces structured and exportable vulnerability reports.

**3️⃣ Phishing URL Detection**

Extracts URL-based lexical, structural, and domain features.

ML/DL classification using scikit-learn and TensorFlow.

Performs heuristic checks + blacklist lookups.

Flags suspicious URLs in real time.

**4️⃣ Correlation Engine**

Merges outputs from all three modules.

Detects multi-stage, coordinated attacks (e.g., phishing → redirect → network compromise).

Validates anomalies across sources to reduce false positives.

Provides a holistic security viewpoint.

**5️⃣ React Dashboard (Frontend)**

Real-time visualization of all detection modules.

Dynamic charts and activity graphs.

Live alerts & notifications.

Traffic analytics, vulnerability reports, and phishing verdicts.

Fetches results through REST APIs from the Python backend.
