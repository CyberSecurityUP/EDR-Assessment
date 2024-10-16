# EDR-Assessment

This notebook outlines the various test cases for evaluating an Endpoint Detection and Response (EDR) system. The following categories cover anti-malware, exploit protection, fileless attack prevention, behavioral protection, ransomware detection, forensic investigation, and endpoint controls.

## Anti-Malware

| Feature | Description | Test |
| ------- | ----------- | ---- |
| Signatures mode | Detects known malware using signature-based detection | Test known malware samples to evaluate signature detection |
| Behavioral document protection | Detect, prevent, and/or quarantine documents with malicious code | Test known malicious documents to assess signature detection |
| Behavioral document protection AI | Detect, prevent, and/or quarantine documents with malicious code using AI | Open malicious documents and save them under a different name |
| Artificial intelligence | AI discovers malware by analyzing files for malicious indicators | Execute malicious files from private malware sources like 0day.today and CTI feeds. Test benign files with strange signatures or behavior |
| Scheduled scans | Schedule anti-malware scans on connected machines | Place malware on the machine and schedule a scan |
| Heuristic analysis | Detects unknown malware through heuristic behavior analysis | Create a custom obfuscated malware and test the heuristic detection capabilities of the EDR |
| Memory scanning | Scans system memory for malicious activity | Load malicious code into memory without writing to disk and evaluate detection |

## Exploit Protection

| Feature | Description | Test |
| ------- | ----------- | ---- |
| Exploit protection mode | Block attempts to exploit vulnerabilities on endpoints | Set up a vulnerable machine (Windows/Linux) and exploit with both simple and advanced techniques |
| Process exclusions | Prevent process injections like Ghosting, Hollow, Classic, and APC | Test process injection techniques and observe detection |
| Stack-based buffer overflow detection | Detects and prevents stack-based buffer overflow attacks | Simulate a stack-based buffer overflow exploit and evaluate EDR's detection |
| Heap-based buffer overflow detection | Detects and prevents heap-based buffer overflow attacks | Simulate a heap-based buffer overflow exploit and evaluate EDR's detection |
| Shellcode execution prevention | Blocks shellcode execution from malicious processes | Inject shellcode into a process and test if EDR can detect and block it |

## Fileless Protection

| Feature | Description | Test |
| ------- | ----------- | ---- |
| Fileless protection mode | Detect and prevent fileless malware attacks | Execute fileless techniques, such as PowerShell and unmanaged execution |
| Download payload | Prevent the execution of downloaded payloads | Download and execute payloads locally |
| Download payload with reputation | Block download commands from domains/IPs with bad reputation | Download payloads from known bad and good reputation websites |
| Script analysis | Prevent the execution of malicious commands and scripts | Execute malicious scripts in PowerShell, Bash, etc. Try bypassing AMSI and other script execution controls |
| .NET floating modules | Prevent the loading of malicious .NET modules | Simulate malicious .NET behavior using IAT and pseudo-ransomware |
| .NET behavioral detection | Detect memory attacks such as DotNetToJScript | Simulate malicious .NET processes and evaluate IAT detection by creating pseudo-ransomware |
| Reflective DLL injection prevention | Blocks reflective DLL injections | Test reflective DLL injection and assess detection |
| WMI abuse detection | Detects the misuse of Windows Management Instrumentation (WMI) | Simulate WMI persistence techniques and evaluate detection |

## Behavioral Execution Protection

| Feature | Description | Test |
| ------- | ----------- | ---- |
| Behavioral execution prevention | Detects and prevents malicious execution based on process behavior | Simulate malicious process behavior using pseudo-ransomware in C# |
| Variant payload prevention | Detects and prevents execution of variant payloads | Create obfuscated/encrypted payloads using simple and advanced techniques |
| Process hollowing detection | Detects and prevents process hollowing attacks | Execute a process hollowing technique and assess EDR's ability to detect it |
| Parent process spoofing detection | Detects suspicious parent-child process relationships | Create a scenario with parent process spoofing and check if the EDR raises an alert |

## Predictive Ransomware Protection

| Feature | Description | Test |
| ------- | ----------- | ---- |
| Predictive ransomware protection | Detect, prevent, and quarantine ransomware | Simulate ransomware attacks using known and custom samples |
| Shadow copy protection | Prevent ransomware from deleting shadow copies | Simulate behavior to delete or disable shadow copies |
| MBR protection | Prevent ransomware from modifying the MBR | Attempt to modify the MBR and evaluate EDR's detection and prevention |
| Rapid recovery | Restore files with a ".restored" suffix | Encrypt system files and check recovery mechanisms |

## Anti-Ransomware

| Feature | Description | Test |
| ------- | ----------- | ---- |
| Anti-Ransomware Mode | Detect, suspend, and prevent ransomware | Execute a known ransomware sample to check if EDR detects and suspends it |
| Canary files | Use canary files to detect ransomware activity | Attempt to encrypt system files and evaluate EDR's response |
| Shadow copy protection | Disable ransomware's ability to delete shadow copies | Simulate behavior to delete or disable shadow copies |
| MBR protection | Prevent ransomware from modifying the MBR | Use known ransomware samples to attempt MBR modification and evaluate detection |
| Behavioral ransomware detection | Detect ransomware based on abnormal encryption behavior | Test various ransomware samples and observe behavioral detection |

## Endpoint Controls

| Feature | Description | Test |
| ------- | ----------- | ---- |
| Device control | Manage removable device controls | Test external USB devices and simulate HID attacks |
| Personal firewall control | Configure personal firewall rules to protect endpoints | Evaluate firewall rules by blocking specific inbound/outbound ports |
| USB blocking | Block unauthorized USB devices | Connect unauthorized USB devices and evaluate response |

## Forensic Investigation

| Feature | Description | Test |
| ------- | ----------- | ---- |
| Non-executable file data collection | Collect metadata from non-executable files involved in attacks | Test collection of metadata from malicious files like PDFs, images, and Word documents |
| File collection | Configure file event collection | Monitor file executions and evaluate the logs and metadata collected |
| Registry collection | Collect data from registry keys modified by malicious processes | Use persistence techniques and evaluate the collection of modified registry keys |
| File transmission | Test sending files to endpoints | Send a file to an endpoint and ensure it arrives correctly |
| Memory forensics | Collect memory dumps for forensic analysis | Trigger memory dump collection and analyze for malicious artifacts |

## Collection Features

| Feature | Description | Test |
| ------- | ----------- | ---- |
| Non-executable file data collection | Collect metadata from non-executable files involved in attacks | Collect metadata from files like PDFs, images, and Word documents |
| File collection | Monitor file events and metadata | Evaluate logs for file executions and monitor behavior |
| Registry collection | Monitor and collect registry changes from malicious processes | Use persistence techniques and collect modified registry keys |
| Network activity collection | Collect network traffic and correlate with attack data | Simulate malicious network traffic and evaluate visibility in EDR |

## Endpoint UI Settings

| Feature | Description | Test |
| ------- | ----------- | ---- |
| System tray icon | Show/hide the EDR icon on the system tray | Check if EDR remains hidden or visible in the operating system |

## Advanced Sensor Options

| Feature | Description | Test |
| ------- | ----------- | ---- |
| Advanced sensor options | Customize sensor settings and enable preview features | Test advanced sensor options and special cases |

## Response Settings

| Feature | Description | Test |
| ------- | ----------- | ---- |
| Incident response tools | Deploy and run incident response tools | Test deployment and data upload to GCP bucket |

## Infrastructure Settings

| Feature | Description | Test |
| ------- | ----------- | ---- |
| Sensor tampering protection | Protect sensors from unauthorized modification | Test tampering attempts |
| EDR process security | Prevent EDR process termination | Test killing the EDR process using BYOVD techniques or known methods (Killer, etc.) |
| Process injection protection | Prevent attempts to inject malicious code into legitimate processes | Test various process injection techniques such as APC injection |


