# DevSecOps Toolbox

A collection of cybersecurity tools and resources that I've used or found valuable during my cyber security analyst training. Entries in italic are added / changed.		
		
# Frameworks & Threat Intelligence		
<table>
<tr><th align="left">Tool</th><th align="left">Website</th><th align="left">Description</th><tr>
<tr><td align="left">Abuse</td><td align="left">https://abuse.ch/</td><td align="left">A platform focused on threat intelligence.</td><tr>
<tr><td align="left">DomainTools</td><td align="left">https://whois.domaintools.com/</td><td align="left">Provides DNS and IP information on a domain.</td><tr>
<tr><td align="left">Talos Intelligence</td><td align="left">https://talosintelligence.com/</td><td align="left">A platform focused on threat intelligence provided by Cisco.</td><tr>
<tr><td align="left">Censys</td><td align="left">https://search.censys.io/</td><td align="left">A search engine for discovering devices and services exposed on the internet, offering insights into vulnerabilities.</td><tr>
<tr><td align="left">Shodan</td><td align="left">https://www.shodan.io/</td><td align="left">A search engine that scans and indexes devices connected to the internet, used for identifying network vulnerabilities.</td><tr>
<tr><td align="left">Mitre Attack</td><td align="left">https://attack.mitre.org/</td><td align="left">A comprehensive framework of adversarial tactics and techniques used by cyber attackers.</td><tr>
<tr><td align="left">Mitre AEP</td><td align="left">https://attack.mitre.org/resources/adversary-emulation-plans/</td><td align="left">Provides adversary emulation plans that simulate cyber threat actors to test and improve security defenses.</td><tr>
<tr><td align="left">Mitre CAR</td><td align="left">https://car.mitre.org/</td><td align="left">Cyber Analytics Repository that offers security analytics to help detect adversary behaviors on networks.</td><tr>
<tr><td align="left">Mitre D3fend</td><td align="left">https://d3fend.mitre.org/</td><td align="left">A knowledge base of cybersecurity countermeasures designed to help organizations protect against attacks.</td><tr>
<tr><td align="left">Mitre Engage</td><td align="left">https://engage.mitre.org/</td><td align="left">A framework designed to guide organizations in planning and executing cyber deception and engagement operations.</td><tr>
<tr><td align="left">LOKI</td><td align="left">https://github.com/Neo23x0/Loki</td><td align="left">A simple scanner that checks for indicators of compromise (IoCs) using YARA rules and other heuristics.</td><tr>
<tr><td align="left">THOR (Lite)</td><td align="left">https://www.nextron-systems.com/thor-lite/</td><td align="left">A professional-grade forensic scanner that detects advanced threats and malicious activity.</td><tr>
<tr><td align="left">Yara</td><td align="left">https://virustotal.github.io/yara/</td><td align="left">A tool aimed at helping malware researchers identify and classify malware by writing flexible detection rules.</td><tr>
<tr><td align="left">FENRIR</td><td align="left">https://github.com/Neo23x0/Fenrir</td><td align="left">A simple IOC scanner for Unix-based systems designed to be easily integrated into security incident response processes.</td><tr>
<tr><td align="left">yarGen</td><td align="left">https://github.com/Neo23x0/yarGen</td><td align="left">A tool for generating YARA rules by extracting relevant strings from malware samples.</td><tr>
<tr><td align="left">valhalla</td><td align="left">https://valhalla.nextron-systems.com/</td><td align="left">A service offering a massive collection of curated YARA rules for detecting malware and threats.</td><tr>
<tr><td align="left">YARAify</td><td align="left">https://yaraify.abuse.ch/</td><td align="left">Provides a feed of YARA rules and allows scanning of files against YARA rules.</td><tr>
<tr><td align="left">OpenCTI</td><td align="left">https://www.opencti.io/</td><td align="left">An open-source platform designed to manage, store, and share cyber threat intelligence information.</td><tr>
<tr><td align="left">MISP</td><td align="left">https://www.misp-project.org/</td><td align="left">An open-source threat intelligence platform for sharing, storing, and correlating indicators of compromise.</td><tr>
<tr><td align="left">IPinfo.io</td><td align="left">https://ipinfo.io/</td><td align="left">Provides geolocation, ownership details, and privacy detection for IP addresses.</td><tr>
<tr><td align="left">URLScan.io</td><td align="left">https://urlscan.io/</td><td align="left">A web sandbox that scans and analyzes URLs for threats, generating detailed reports.</td><tr>
<tr><td align="left">DomainTools Whois</td><td align="left">https://whois.domaintools.com/</td><td align="left">Retrieves domain registration details, including ownership, creation date, and DNS information.</td><tr>
<tr><td align="left">VirusTotal</td><td align="left">https://www.virustotal.com/gui/</td><td align="left">Analyzes suspicious files and URLs to detect malware and shares findings with the security community.</td><tr>
</table>	
	
Network Security		
		
Tool	Website	Description
Zenmap	https://nmap.org/zenmap/	The official graphical user interface (GUI) for Nmap.
Snort	https://www.snort.org/	An open-source intrusion detection and prevention system (IDS/IPS).
NetworkMiner	https://www.netresec.com/?page=NetworkMiner	A network forensic analysis tool (NFAT) for extracting and analyzing data from network traffic.
Wireshark	https://www.wireshark.org/	A network protocol analyzer used for network troubleshooting, analysis, and protocol development.
TShark	https://tshark.dev/	The command-line version of Wireshark, offering similar functionalities for capturing and analyzing network traffic via CLI.
Brim	https://www.brimdata.io	The graphical user interface (GUI) for Zeek.
		
Endpoint Security & SIEM		
		
Tool	Website	Description
TCPView	https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview	Displays active TCP and UDP connections, including process ownership and connection states.
Process Explorer	https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer	Provides detailed information about running processes.
Wevtutil.exe	https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil	Command-line tool for managing Windows Event Logs, including querying, exporting, and clearing logs.
Sysmon	https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon	Monitors and logs detailed system activity to Windows Event Logs for security analysis.
Osquery	https://www.osquery.io	Uses SQL-like queries to collect and analyze operating system data for monitoring, compliance, and security.
Wazuh	https://wazuh.com/	A free SIEM platform for threat detection, compliance, and IT security monitoring.
Process Hacker	https://processhacker.sourceforge.io/	Open-source tool for monitoring processes, detecting malicious activity, and troubleshooting.
Autoruns	https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns	Shows programs configured to run at system startup or login in detail.
Procdump	https://learn.microsoft.com/en-us/sysinternals/downloads/procdump	Captures process dumps during CPU spikes or application crashes for debugging purposes.
Splunk	https://www.splunk.com/	A platform for collecting, indexing, and analyzing machine-generated data in real-time.
		
DFIR		
		
Tool	Website	Description
FTK Imager	https://www.exterro.com/digital-forensics-software/ftk-imager	A forensic imaging tool used to preview, image, and analyze digital evidence.
RegRipper	https://github.com/keydet89/RegRipper3.0	Extracts and analyzes Windows registry data using plugins for incident response and forensics.
Zimmerman's Registry Explorer	https://ericzimmerman.github.io/	Parses and analyzes Windows registry hives for forensic artifacts.
ShellBagExplorer	https://ericzimmerman.github.io/	Analyzes ShellBag registry data to track folder access and browsing history.
Registry Viewer	https://ericzimmerman.github.io/	Examines Windows registry files for forensic analysis of keys, values, and settings.
Autopsy	https://www.autopsy.com	Open-source digital forensics platform for investigating and analyzing hard drives and files.
Redline	https://fireeye.market/apps/211364	Provides host investigative capabilities to detect malicious activity through memory and file analysis.
KAPE	https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape	Collects and processes forensic artifacts efficiently during investigations.
Volatility	https://github.com/volatilityfoundation/volatility	An open-source memory forensics framework for analyzing RAM dumps.
Velociraptor	https://docs.velociraptor.app/	Endpoint monitoring and digital forensics tool.
The Hive	https://github.com/TheHive-Project/TheHive	An open-source incident response platform for managing security events collaboratively.
PE Tree	https://github.com/blackberry/pe_tree	Visualizes Portable Executable (PE) files to aid malware analysis.
Olevba	https://github.com/decalage2/oletools/wiki/olevba	Analyzes Microsoft Office documents to detect and extract malicious VBA macros and indicators of compromise.
		
Sandboxes		
		
Tool	Website	Description
Cuckoo Sandbox	https://cuckoosandbox.org/	Open-source automated malware analysis system for dynamic analysis of suspicious files and URLs.
CAPE Sandbox	https://capev2.readthedocs.io/en/latest/index.html	Malware analysis sandbox focused on unpacking and analyzing malicious payloads and executables.
Any.run	https://any.run/	Interactive online malware sandbox allowing real-time analysis of suspicious files and activities.
Hybrid Analysis	https://www.hybrid-analysis.com/	Free malware analysis service powered by Falcon Sandbox for static and dynamic threat analysis.
		
Phishing & Mails		
		
Tool	Website	Description
Phish Tool	https://phishtool.com/	A platform designed for detecting, analyzing, and managing phishing threats.
Message Header Analyzer	https://mha.azurewebsites.net/	Parses and analyzes email headers to trace the path of messages and identify potential issues.
Mail Header Analyzer	https://mailheader.org/	Makes email headers legible by parsing records for detailed analysis of message routing.
MXToolbox	https://mxtoolbox.com/	Provides tools to analyze DNS, MX records, and email server configurations for troubleshooting.
PhishTank	https://phishtank.com/	Community-driven platform to track, verify, and share information about phishing websites.
Spamhaus	https://www.spamhaus.org/	Offers IP and domain reputation services to detect and block spam, malware, and other threats.
Google Messageheader	https://toolbox.googleapps.com/apps/messageheader/	Analyzes email headers to identify delivery delays, their sources, and responsible parties.
Phishing IR Playbook	https://github.com/counteractive/incident-response-plan-template/blob/master/playbooks/playbook-phishing.md	A comprehensive playbook for investigating, remediating, and communicating during phishing incidents.
		
Miscellaneous		
		
Tool	Website	Description
URL2PNG	https://www.url2png.com/	Captures snapshots of websites through an intuitive API for integration into apps or workflows.
Wannabrowser	https://www.wannabrowser.net/	Allows viewing HTML source code of websites using different user-agent perspectives to detect cloaking.
CVE Crowd	https://cvecrowd.com/	A platform for discussing and sharing information about CVEs and vulnerabilities.
Fedisec Feeds	https://fedisecfeeds.github.io/	Aggregates security-related data, including CVE updates, in JSON format for easy access.
