"""
Learning Engine – Educational Context, Skill-Tracking, and
OS-Aware Guidance (Windows • Linux • macOS)

This module explains cybersecurity concepts while users run the SecOps
CLI Wrapper.  It adapts its content to the host operating system in three
ways:
1.  Adds OS-specific tool-installation hints.
2.  Provides platform-relevant defensive guidance.
3.  Suggests practice labs that match the user’s environment.
"""

import json
import platform
from typing import Dict, List, Any
from datetime import datetime


class LearningSystem:
    def __init__(self) -> None:
        # Detect host OS once at startup
        self.current_os: str = platform.system().lower()   # windows / linux / darwin
        self.learning_content: Dict[str, Dict] = self._load_learning_content()
        self.skill_tracker: Dict[str, List[Dict[str, Any]]] = {}
        self.session_progress: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # 1.  LOAD ALL LEARNING MATERIAL (generic + per-OS additions)
    # ------------------------------------------------------------------ #
    def _load_learning_content(self) -> Dict[str, Dict]:
        """Return a merged dictionary of generic and OS-specific learning notes."""
        generic: Dict[str, Dict] = {
            'nmap': {
                'tool_description': 'Network Mapper – the Swiss-Army knife of network discovery',
                'concepts': [
                    'Port-scanning techniques (TCP SYN, TCP Connect, UDP)',
                    'Service/version detection and OS fingerprinting',
                    'Network-topology mapping and host discovery',
                    'Stealth scanning and firewall evasion'
                ],
                'real_world_application': (
                    'Used by defenders for asset inventory and by attackers to map targets'
                ),
                'defensive_perspective': (
                    'Shows which services are exposed and need hardening or firewall rules'
                ),
                'common_flags': {
                    '-sS': 'TCP SYN scan – stealthier than a full TCP connect',
                    '-sV': 'Version detection – identifies running software',
                    '-O':  'OS detection – attempts to fingerprint the OS',
                    '-p-': 'Scan all 65 535 ports instead of the default list'
                }
            },
            'nikto': {
                'tool_description': 'Web-server scanner for dangerous files and misconfigurations',
                'concepts': [
                    'Web-server fingerprinting & outdated-software checks',
                    'Common-file enumeration and CGI script testing',
                    'HTTP-method checks and header analysis'
                ],
                'real_world_application': 'First-line security sweep for web applications',
                'defensive_perspective': 'Spots easy misconfigurations before attackers do',
                'vulnerability_categories': [
                    'Default files & directories',
                    'Outdated server software',
                    'Insecure CGI scripts',
                    'Server-config issues (TRACE enabled, etc.)'
                ]
            },
            'clamav': {
                'tool_description': 'Open-source antivirus engine for malware detection',
                'concepts': [
                    'Signature-based detection and heuristic analysis',
                    'Archive & file-format scanning',
                    'Real-time versus on-demand protection'
                ],
                'real_world_application': 'Mail-gateway filtering and endpoint protection',
                'defensive_perspective': (
                    'Adds an extra malware layer in a defense-in-depth strategy'
                )
            }
        }

        # ---------- Per-OS additions ----------------------------------- #
        os_hints = {
            'windows': {
                'nmap': {
                    'os_setup': 'Download “nmap-<ver>.msi” from nmap.org and tick '
                                '“Add to PATH” during install.'
                },
                'nikto': {
                    'os_setup': 'Install Strawberry Perl, then unzip Nikto and run '
                                '“perl nikto.pl …” from CMD/PowerShell.'
                },
                'clamav': {
                    'os_setup': 'Use the official “clamav-x64.msi”, then open an '
                                'Admin CMD and run “freshclam” to update signatures.'
                },
                '_defensive_tips': [
                    'Enable Windows Defender Real-Time Protection.',
                    'Use PowerShell “Set-ExecutionPolicy AllSigned” to reduce script risk.'
                ],
                '_practice_lab': (
                    'Spin up an isolated Hyper-V VM and practise scanning it from the host.'
                )
            },
            'linux': {
                'nmap': {
                    'os_setup': 'sudo apt install nmap   # or yum/dnf on RHEL-based distros'
                },
                'nikto': {
                    'os_setup': 'sudo apt install nikto   # or clone Nikto from GitHub'
                },
                'clamav': {
                    'os_setup': 'sudo apt install clamav clamav-daemon && sudo freshclam'
                },
                '_defensive_tips': [
                    'Harden SSH: disable password login, use Fail2Ban.',
                    'Keep packages updated: “sudo unattended-upgrade”.'
                ],
                '_practice_lab': (
                    'Use two local LXC containers – scan one from the other to stay safe.'
                )
            },
            'darwin': {  # macOS
                'nmap': {
                    'os_setup': 'brew install nmap'
                },
                'nikto': {
                    'os_setup': 'brew install nikto   # needs Xcode CLI tools'
                },
                'clamav': {
                    'os_setup': 'brew install clamav && sudo freshclam'
                },
                '_defensive_tips': [
                    'Ensure Gatekeeper is enabled (System Settings ➜ Privacy & Security).',
                    'Review application-permission prompts carefully.'
                ],
                '_practice_lab': (
                    'Create a Docker bridge network and run a vulnerable web app image; '
                    'scan it from the host.'
                )
            }
        }

        # Merge generic with the current-OS hints
        os_data = os_hints.get(self.current_os, {})
        for tool_name, addon in os_data.items():
            if tool_name.startswith('_'):     # special keys: defensive tips, labs
                continue
            generic.setdefault(tool_name, {}).update(addon)

        # Store global OS-wide extras for later printing
        self.os_defensive_tips: List[str] = os_data.get('_defensive_tips', [])
        self.os_practice_lab: str = os_data.get('_practice_lab', '')

        return generic

    # ------------------------------------------------------------------ #
    # 2.  HIGH-LEVEL INTRO + PLATFORM DISCLOSURE
    # ------------------------------------------------------------------ #
    def show_intro(self) -> None:
        print("\n🎓  LEARNING MODE ACTIVATED")
        print("=" * 60)
        print(f"Detected platform :  {self.current_os.title()}")
        print("This mode explains each action so you learn while you scan.\n")

        print("Key Learning Objectives:")
        print(" • Understand why a specific tool is chosen")
        print(" • Follow the logical flow of a security assessment")
        print(" • Compare offensive and defensive perspectives")
        print(" • Track your own skill growth\n")

        if self.os_defensive_tips:
            print("🔐  Quick Defensive Tips for Your OS:")
            for tip in self.os_defensive_tips:
                print(f"   – {tip}")
        if self.os_practice_lab:
            print(f"\n🧪  Suggested Safe-Practice Lab:\n   {self.os_practice_lab}")
        print("=" * 60)

    # ------------------------------------------------------------------ #
    # 3.  CONTEXTUAL EXPLANATIONS & RESULT INTERPRETATION
    # ------------------------------------------------------------------ #
    def explain_target_analysis(self, analysis: Dict[str, Any]) -> None:
        """Explain why particular tools were selected for the detected target."""
        print("\n📚  TARGET ANALYSIS")
        print("-" * 50)
        print(f"Target        : {analysis.get('target')}")
        print(f"Classified as : {analysis.get('target_type').upper()}")
        print(f"Scan Strategy : {analysis.get('scan_strategy').upper()}")
        print(f"Platform      : {self.current_os.title()}\n")

        logic = {
            'ip':    'Network reconnaissance first to discover live services.',
            'url':   'Combine host scan + web vulnerability scan.',
            'domain': 'Resolve DNS ➜ map infrastructure ➜ scan exposed hosts.',
            'file':  'Run signature & heuristic malware analysis.'
        }
        print("Why this matters:", logic.get(analysis.get('target_type'), 'N/A'), "\n")

        print("Recommended Tools & Learning Focus:")
        for idx, tool in enumerate(analysis.get('recommended_tools', []), 1):
            print(f" {idx}. {tool['name'].upper()} – {tool['learning_objective']}")

    def explain_tool_purpose(self, tool: str, result: Dict[str, Any]) -> None:
        """Print educational notes and interpret a tool’s results."""
        info = self.learning_content.get(tool, {})
        if not info:
            return

        print(f"\n🔧  TOOL: {tool.upper()}")
        print("-" * 50)
        print(f"Purpose : {info['tool_description']}")
        if 'os_setup' in info:
            print(f"Setup   : {info['os_setup']}")

        print("\nKey Concepts:")
        for c in info.get('concepts', []):
            print(f" • {c}")

        print("\nReal-World Application:")
        print(f" {info.get('real_world_application')}")

        if 'defensive_perspective' in info:
            print("\nDefensive Perspective:")
            print(f" {info['defensive_perspective']}")

        # ------------ Interpret sample output -------------------------- #
        if result.get('success'):
            self._interpret_results(tool, result)
        else:
            self._print_fail_hints(tool)

    def _print_fail_hints(self, tool: str) -> None:
        print("\n❌  The tool did not run successfully.")
        print("   • Check if it is installed and in your PATH.")
        print("   • Verify permissions (Administrator/sudo may be required).")
        os_hint = self.learning_content.get(tool, {}).get('os_setup', '')
        if os_hint:
            print(f"   • Installation hint for this OS: {os_hint}")

    # ------------------------------------------------------------------ #
    # 4.  RESULT-SPECIFIC EDUCATIONAL NOTES
    # ------------------------------------------------------------------ #
    def _interpret_results(self, tool: str, result: Dict[str, Any]) -> None:
        print("\n📊  RESULT SUMMARY & TAKEAWAYS")

        if tool == 'nmap':
            ports = result.get('data', {}).get('open_ports', [])
            if ports:
                print(f" • Open ports discovered: {ports}")
                print("   – Each open port widens the attack surface.")
                print("   – Unneeded services should be disabled or firewalled.\n")
            else:
                print(" • No open ports detected – network exposure appears minimal.\n")

        elif tool == 'nikto':
            vulns = result.get('data', {}).get('vulnerabilities_found', 0)
            print(f" • Vulnerabilities flagged: {vulns}")
            if vulns:
                print("   – Treat high-risk findings first (e.g., default files, RCE bugs).")
            else:
                print("   – No obvious misconfigs, but deeper manual testing is still needed.\n")

        elif tool == 'clamav':
            infected = result.get('data', {}).get('infected_files', 0)
            print(f" • Infected files: {infected}")
            if infected:
                print("   – Quarantine or delete the files and investigate how they arrived.\n")
            else:
                print("   – No malware signatures detected in scanned files.\n")

    # ------------------------------------------------------------------ #
    # 5.  LEARNING TOPIC DISPATCHERS (unchanged logic, now OS-aware)
    # ------------------------------------------------------------------ #
    #   scanning, vulnerabilities, tools, methodology – same as earlier
    # ------------------------------------------------------------------ #
    # ...  (existing _teach_* methods remain unchanged) ...

    # ------------------------------------------------------------------ #
    # 6.  PROGRESS TRACKING (unchanged)
    # ------------------------------------------------------------------ #
    def track_progress(self, skill_area: str, achievement: str) -> None:
        entry = {
            'achievement': achievement,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'platform': self.current_os
        }
        self.skill_tracker.setdefault(skill_area, []).append(entry)
        self.session_progress.append(entry)
