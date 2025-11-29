# SOC Monitoring Lab - Threat Detection & Response

- **Platform**: Wazuh SIEM + Windows + Linux
- **Goal**:

Demonstrate real detection, threat hunting, and automated response quickly and clearly.

### Lab Environment

- **Wazuh Manager**: Linux
- **Windows 10 Endpoint**: Sysmon + Wazuh Agent
- **Linux Endpoint**: SSH brute-force detection

---

### Windows Registry Persistence Detection

- **MITRE**: T1547.001
- **Action**: Add/remove Run key

- Registry Key Monitored:

`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`

- Attack Command:

`Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "MalwarePersistence" -Value "C:\malware.exe"`

- Wazuh Detection

![Wazuh Dashboard](./assets/SOC-Monitoring-Wazuh-SIEM-Threat-Detection_win_01.png)
![Wazuh Dashboard](./assets/SOC-Monitoring-Wazuh-SIEM-Threat-Detection_win_02.png)

### File Integrity Monitoring (FIM)

- **Action**: Create or modify files

- Monitored Directory

```sh
C:\Users\win10\Desktop\wazuh
```

- Test File Creation: `echo "test_malware" > C:\Users\win10\Desktop\wazuh\test_malware.exe`

- Wazuh Detection:

![Wazuh Dashboard](./assets/SOC-Monitoring-Wazuh-SIEM-Threat-Detection_win_03.png)

### Malware Hash Detection

- **MITRE**: T1204.002
- **Action**: Match file hashes with known malware

- Hash List:

`/var/ossec/etc/lists/malware-hashes`

```sh
e0ec2cd43f71c80d42cd7b0f17802c73:mirai_botnet
55142f1d393c5ba7405239f232a6c059:xbash_malware
5d41402abc4b2a76b9719d911017c592:test_hello
```

- Wazuh Detection:

![Wazuh Dashboard](./assets/SOC-Monitoring-Wazuh-SIEM-Threat-Detection_win_04.png)

### VirusTotal Integration + Automatic File Removal

**Action**: Detect file -> Send hash to VirusTotal -> Auto-delete

- Malware Test:

  `Invoke-WebRequest https://secure.eicar.org/eicar.com.txt -OutFile "virus.com.txt"`

- Detection & Response Flow:

  - Wazuh detects file creation
  - Sends hash to VirusTotal -> 65 engines detect
  - Triggers remove-threat.exe
  - File automatically deleted

- Wazuh Logs:

![Wazuh Dashboard](./assets/SOC-Monitoring-Wazuh-SIEM-Threat-Detection_win_05.png)

### Sysmon Threat Hunting

- Monitored Events:

  - Event ID 22 -> DNS Query
  - Event ID 1 -> Process Creation
  - Event ID 3 -> Network Connection
  - Event ID 10 -> Process Injection

- DNS Monitoring:

![Wazuh Dashboard](./assets/SOC-Monitoring-Wazuh-SIEM-Threat-Detection_win_06.png)

### Windows Defender Threat Detection

- **Action**: Defender alerts forwarded to Wazuh

- Detection:

![Wazuh Dashboard](./assets/SOC-Monitoring-Wazuh-SIEM-Threat-Detection_win_07.png)

### RDP Brute Force Detection & Auto-Blocking

- **MITRE**: T1110.003
- **Action**: 3 failed logins -> Firewall block

- Wazuh Rule:

```sh
<rule id="100900" level="10" frequency="3" timeframe="120">
  <if_matched_sid>60122</if_matched_sid>
  <description>RDP Bruteforce detected</description>
</rule>
```

![Wazuh Dashboard](./assets/SOC-Monitoring-Wazuh-SIEM-Threat-Detection_win_08.png)

- Auto-Response:

![Wazuh Dashboard](./assets/SOC-Monitoring-Wazuh-SIEM-Threat-Detection_win_09.png)

---

### SSH Brute Force Detection (Linux)

- **MITRE**: T1110
- **Action**: 3 failed SSH logins -> IP blocked via Active Response

- Attack Simulation:

`hydra -l root -P passwords.txt ssh://192.168.1.40`

- Wazuh Detection:

- Auto-Response:

`iptables -A INPUT -s attacker_ip -j DROP`

### PAM Account Protection

- **Action**: 3 failed login attempts -> PAM account disabled

- Wazuh Rule:

```sh
<rule id="120100" level="10" frequency="3" timeframe="120">
  <if_matched_sid>5503</if_matched_sid>
  <description>Password guessing attack detected</description>
</rule>
```

- Auto-Response: Account automatically disabled via `disable-account`

---

## Summary

- Techniques Covered: 8+ MITRE ATT&CK Techniques
- Detection Rate: 100% of simulated attacks
- Response Time: < 60 seconds for automated remediation
- Platforms: Windows + Linux

- Key Strengths:

  - Real-time FIM and registry monitoring
  - Automated malware analysis and removal
  - Multi-layer brute force protection
  - Enterprise-grade threat hunting
  - Proven automation and response workflows
