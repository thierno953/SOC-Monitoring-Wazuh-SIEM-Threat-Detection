# SOC Monitoring Lab – Wazuh, Sysmon & Threat Response

Hands-on SOC lab focused on real attacks, detection, and automated responses using a lightweight enterprise setup.

- **Tools used**:

  - Wazuh SIEM
  - Sysmon (for Windows visibility)
  - Linux security logs
  - VirusTotal integration
  - Active Response automation

## Lab Environment

| Component             | Role                             |
| --------------------- | -------------------------------- |
| Wazuh Manager (Linux) | Central SIEM and response engine |
| Windows 10 Endpoint   | Wazuh Agent + Sysmon             |
| Linux Endpoint        | SSH monitoring & Active Response |

Controlled attacks were executed to test detection rules, file integrity monitoring, malware hash detection, persistence detection, and automated blocking on both Windows and Linux systems.

---

## Key Attacks & Detections

### Windows Registry Persistence

- **MITRE**: T1547.001
- **Action**: Add/remove Run key for persistence

- **Test Command**:

```sh
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "MalwarePersistence" -Value "C:\malware.exe"
```

- **Detection**: Wazuh monitors Run key changes and alerts on suspicious entries.

![Wazuh Dashboard](./assets/SOC-Monitoring-Wazuh-SIEM-Threat-Detection_win_01.png)
![Wazuh Dashboard](./assets/SOC-Monitoring-Wazuh-SIEM-Threat-Detection_win_02.png)

### File Integrity Monitoring (FIM)

- **Action**: Detect new or modified files
- **Monitored Folder**: `C:\Users\win10\Desktop\wazuh`

- **Test Command**: `echo "test_malware" > C:\Users\win10\Desktop\wazuh\test_malware.exe`

- **Detection**: Wazuh alerts on new or modified files.

![Wazuh Dashboard](./assets/SOC-Monitoring-Wazuh-SIEM-Threat-Detection_win_03.png)

### Malware Hash Detection

- **MITRE**: T1204.002
- **Action**: Match file hashes with known malware
- **Hash List**: `/var/ossec/etc/lists/malware-hashes`

```sh
e0ec2cd43f71c80d42cd7b0f17802c73:mirai_botnet
55142f1d393c5ba7405239f232a6c059:xbash_malware
5d41402abc4b2a76b9719d911017c592:test_hello
```

- **Detection**: Alerts on known malware hashes and triggers automatic response.

![Wazuh Dashboard](./assets/SOC-Monitoring-Wazuh-SIEM-Threat-Detection_win_04.png)

### VirusTotal Integration + Auto File Removal

- **Action**: Detect file → send hash to VirusTotal → delete if malicious

- **Test File**: `Invoke-WebRequest https://secure.eicar.org/eicar.com.txt -OutFile "virus.com.txt"`

- **Flow**: Wazuh detects → VirusTotal confirms → file deleted automatically.

![Wazuh Dashboard](./assets/SOC-Monitoring-Wazuh-SIEM-Threat-Detection_win_05.png)

### Sysmon Threat Hunting (Windows)

- **Monitored Event**:

  - Event ID 1 → Process creation
  - Event ID 3 → Network connection
  - Event ID 10 → Process injection
  - Event ID 22 → DNS query

- **Detection**: Suspicious behavior is detected and forwarded to Wazuh.

![Wazuh Dashboard](./assets/SOC-Monitoring-Wazuh-SIEM-Threat-Detection_win_06.png)

### Windows Defender Alerts

- Defender alerts are forwarded to Wazuh for correlation and analysis.

![Wazuh Dashboard](./assets/SOC-Monitoring-Wazuh-SIEM-Threat-Detection_win_07.png)

### RDP Brute Force Detection

- **MITRE**: T1110.003
- **Action**: 3 failed logins → Firewall block via Wazuh Active Response

```sh
<rule id="100900" level="10" frequency="3" timeframe="120">
  <if_matched_sid>60122</if_matched_sid>
  <description>RDP Brute Force detected</description>
</rule>
```

![Wazuh Dashboard](./assets/SOC-Monitoring-Wazuh-SIEM-Threat-Detection_win_08.png)

- **Auto Response**: IP blocked via Windows Firewall.

![Wazuh Dashboard](./assets/SOC-Monitoring-Wazuh-SIEM-Threat-Detection_win_09.png)

---

### SSH Brute Force Detection (Linux)

- **MITRE**: T1110
- **Action**: 3 failed SSH logins → IP blocked via iptables

- **Attack Simulation**:

```sh
hydra -l root -P passwords.txt ssh://192.168.1.40
```

- **Wazuh Rule**:

```sh
<rule id="120000" level="12" frequency="3" timeframe="120" ignore="300">
  <if_matched_sid>5763</if_matched_sid>
  <if_matched_sid>5503</if_matched_sid>
  <if_matched_sid>5760</if_matched_sid>
  <if_matched_sid>5710</if_matched_sid>
  <if_matched_sid>5551</if_matched_sid>
  <same_source_ip/>
  <description>SSH Brute Force detected: 3 failed attempts from the same IP within 2 minutes</description>
  <group>ssh, brute_force</group>
</rule>
```

- Active Response Script (`active-response/bin/block-ip.sh`):

```sh
#!/bin/bash
IP=$1

if [ -n "$IP" ]; then
    iptables -A INPUT -s "$IP" -j DROP
    logger "[Wazuh Active Response] SSH brute-force IP blocked: $IP"
fi
```

- **Active Response Config**:

```sh
<active-response>
  <command>block-ip</command>
  <location>local</location>
  <rules_id>120000</rules_id>
  <timeout>600</timeout>
</active-response>
```

### PAM / Account Protection (Account Lock)

- **Action**: 3 failed login attempts → account automatically disabled

- **Wazuh Rule**:

```sh
<rule id="120100" level="10" frequency="3" timeframe="120">
  <if_matched_sid>5503</if_matched_sid>
  <description>Password guessing attack detected: 3 failed login attempts</description>
  <group>pam, brute_force</group>
</rule>
```

- Active Response Script (`active-response/bin/disable-account.sh`):

```sh
#!/bin/bash
USER=$2

if [ -n "$USER" ] && id "$USER" &>/dev/null; then
    usermod -L "$USER"
    logger "[Wazuh Active Response] Account disabled due to multiple failed logins: $USER"
fi
```

- **Active Response Config**:
 
```sh
<active-response>
  <command>disable-account</command>
  <location>local</location>
  <rules_id>120100</rules_id>
  <timeout>0</timeout>
</active-response>
```

---

## Lessons Learned

- Wazuh detects persistence, brute-force attacks, and malware quickly.
- Combining Windows Sysmon and Linux logs improves coverage.
- Automated responses (IP blocking, account lock) are effective but need careful tuning.
- Wazuh provides a clear audit trail for incident response and forensic investigation.
- All simulated attacks were detected and mitigated in under 60 seconds.
