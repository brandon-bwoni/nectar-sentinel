# Nectar Sentinel Honeypot

## 1. Project Overview

### Title
Python-based Honeypot Application

### Description
This Python-based honeypot application is designed to emulate a vulnerable system to attract and monitor potential attackers. It features an SSH server and a web server, both configured to capture suspicious activities. By simulating weak security, the app gathers valuable insights into malicious behavior and attack patterns, enhancing understanding of cybersecurity threats.

### Technologies Used
- **Programming Language**: Python
- **SSH Server**: Built using `paramiko` for SSH protocol implementation.
- **Web Server**: Powered by Flask for simulating web vulnerabilities.
- **Cryptography**: Enhanced security for simulated credentials and data using `bcrypt` and `cryptography`.

---

## 2. Features

### Core Features
1. **SSH Honeypot**:
   - Simulates an SSH server with weak credentials to attract attackers.
   - Logs login attempts, including usernames, passwords, and IP addresses.

2. **Web Server Honeypot**:
   - Hosts a mock vulnerable web application to emulate insecure configurations.
   - Captures and logs suspicious requests and potential exploit attempts.

3. **Data Logging and Monitoring**:
   - Maintains detailed logs of all interactions.
   - Captures metadata such as timestamps, attacker IPs, and attempted commands.

4. **Encryption and Security**:
   - Uses `bcrypt` and `cryptography` for encrypting logs and credentials.
   - Simulates security mechanisms to make the honeypot more convincing.

---

## 3. Installation and Setup

### Prerequisites
- Python 3.8+
- pip package manager

### Required Packages
The application relies on the following dependencies (versions specified):
```plaintext
bcrypt==4.2.1
blinker==1.9.0
cffi==1.17.1
click==8.1.8
colorama==0.4.6
cryptography==44.0.0
Flask==3.1.0
itsdangerous==2.2.0
Jinja2==3.1.5
MarkupSafe==3.0.2
paramiko==3.5.0
pycparser==2.22
PyNaCl==1.5.0
Werkzeug==3.1.3
```

### Installation Steps
1. Clone the repository:
   ```bash
   git clone <repository-url>
   ```
2. Navigate to the project directory:
   ```bash
   cd python-honeypot
   ```
3. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
5. Configure settings:
   - Edit `config.py` to set SSH credentials, logging paths, and other configurations.

6. Run the application:
   ```bash
   python app.py
   ```

---

## 4. Usage

### Starting the Honeypot
- Ensure the application is running:
  ```bash
  python app.py
  ```
- The SSH server will listen on a specified port (default: `22`).
- The web server will be accessible at `http://<host>:5000`.

### Interpreting Logs
- SSH logs:
  - Captures login attempts, failed commands, and attacker IPs.
  - Stored in `logs/ssh_logs.txt`.
- Web logs:
  - Records HTTP requests, headers, and payloads.
  - Stored in `logs/web_logs.txt`.

### Example Workflow
1. Deploy the honeypot in a controlled network environment.
2. Monitor the logs in real time to observe incoming activity.
3. Analyze patterns to identify potential vulnerabilities.

---

## 5. Understanding Honeypots

### What is a Honeypot?
A honeypot is a decoy system designed to mimic a real target for attackers. It intentionally contains vulnerabilities to attract malicious actors, enabling organizations to study attack strategies, identify weaknesses, and enhance security measures.

### Why Use Honeypots?
- **Threat Detection**: Identify and monitor unauthorized access attempts.
- **Behavior Analysis**: Understand attacker methodologies and toolkits.
- **Improved Security**: Use gathered data to strengthen actual systems.

---

## 6. Challenges and Learnings

### Challenges
- Configuring realistic but vulnerable environments.
- Balancing between authenticity and secure isolation from production systems.
- Analyzing and interpreting large volumes of log data.

### Learnings
- Enhanced understanding of SSH and web protocols.
- Practical experience with monitoring and logging tools.
- Insights into real-world attack patterns and threat mitigation.

---

## 7. Future Improvements
- **Enhanced Realism**: Add more services (e.g., FTP, database) to simulate a complete environment.
- **Automated Analysis**: Integrate tools for real-time log analysis and alerting.
- **Dashboard**: Create a graphical dashboard to visualize attack data.
- **Machine Learning**: Use ML algorithms to classify and predict attack behaviors.

---

## 8. References
- [Paramiko Documentation](http://www.paramiko.org/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Cryptography Library](https://cryptography.io/en/latest/)

