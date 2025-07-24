"""
Decision Engine - Cross-Platform Intelligent Tool Selection and Workflow Orchestration

This module analyzes targets and scan results to intelligently determine which 
security tools to use and in what sequence, while providing educational context.
Works seamlessly on Windows, Linux, and macOS.
"""

import re
import socket
import urllib.parse
import platform
import shutil
import os
from typing import Dict, List, Any, Optional
from pathlib import Path

class DecisionEngine:
    def __init__(self):
        self.current_os = platform.system().lower()
        self.tool_capabilities = self._load_tool_capabilities()
        self.decision_rules = self._load_decision_rules()
        self.tool_paths = self._detect_tool_paths()

    def _detect_tool_paths(self) -> Dict[str, Optional[str]]:
        """Detect installed security tools across different operating systems."""
        tools_to_detect = ['nmap', 'nikto', 'clamscan', 'john']
        detected_tools = {}
        
        for tool in tools_to_detect:
            # Use shutil.which() which works cross-platform
            tool_path = shutil.which(tool)
            
            if not tool_path and self.current_os == 'windows':
                # Check common Windows installation paths
                windows_paths = [
                    Path(r"C:\Program Files\Nmap\nmap.exe") if tool == 'nmap' else None,
                    Path(r"C:\Program Files (x86)\Nmap\nmap.exe") if tool == 'nmap' else None,
                    Path(r"C:\Program Files\ClamAV\clamscan.exe") if tool == 'clamscan' else None,
                    Path(r"C:\Program Files (x86)\ClamAV\clamscan.exe") if tool == 'clamscan' else None,
                ]
                
                for path in windows_paths:
                    if path and path.exists():
                        tool_path = str(path)
                        break
            
            detected_tools[tool] = tool_path
        
        return detected_tools

    def _load_tool_capabilities(self) -> Dict[str, Dict]:
        """Define what each security tool is good for - cross-platform compatible."""
        return {
            'nmap': {
                'purpose': 'Network discovery and port scanning',
                'input_types': ['ip', 'domain', 'network'],
                'output_types': ['open_ports', 'services', 'os_detection'],
                'prerequisites': [],
                'learning_value': 'Essential for understanding network topology and attack surface',
                'cross_platform': True,
                'install_commands': {
                    'windows': 'Download from https://nmap.org/download.html',
                    'linux': 'sudo apt install nmap (Ubuntu/Debian) or sudo yum install nmap (RHEL/CentOS)',
                    'darwin': 'brew install nmap'
                }
            },
            'nikto': {
                'purpose': 'Web server vulnerability scanning',
                'input_types': ['url', 'domain'],
                'output_types': ['web_vulnerabilities', 'server_info', 'security_issues'],
                'prerequisites': ['open_port_80', 'open_port_443'],
                'learning_value': 'Teaches common web vulnerabilities and server misconfigurations',
                'cross_platform': True,
                'install_commands': {
                    'windows': 'Install Perl from strawberryperl.com, then download Nikto from GitHub',
                    'linux': 'sudo apt install nikto (Ubuntu/Debian) or git clone from GitHub',
                    'darwin': 'brew install nikto or git clone from GitHub'
                }
            },
            'clamav': {
                'purpose': 'Malware detection and file scanning',
                'input_types': ['file', 'directory'],
                'output_types': ['malware_detection', 'virus_signatures'],
                'prerequisites': [],
                'learning_value': 'Demonstrates signature-based malware detection techniques',
                'cross_platform': True,
                'install_commands': {
                    'windows': 'Download ClamAV for Windows from https://www.clamav.net/downloads',
                    'linux': 'sudo apt install clamav clamav-daemon',
                    'darwin': 'brew install clamav'
                }
            },
            'john': {
                'purpose': 'Password strength testing and cracking',
                'input_types': ['password_hash', 'password_file'],
                'output_types': ['cracked_passwords', 'password_strength'],
                'prerequisites': [],
                'learning_value': 'Shows importance of strong password policies and hashing',
                'cross_platform': True,
                'install_commands': {
                    'windows': 'Download John the Ripper from https://www.openwall.com/john/',
                    'linux': 'sudo apt install john',
                    'darwin': 'brew install john'
                }
            },
            'burp': {
                'purpose': 'Advanced web application security testing',
                'input_types': ['url', 'web_app'],
                'output_types': ['detailed_web_vulns', 'injection_points', 'auth_issues'],
                'prerequisites': ['web_service_detected'],
                'learning_value': 'Deep dive into web application security testing methodology',
                'cross_platform': True,
                'install_commands': {
                    'windows': 'Download Burp Suite from https://portswigger.net/burp',
                    'linux': 'Download Burp Suite from https://portswigger.net/burp',
                    'darwin': 'Download Burp Suite from https://portswigger.net/burp'
                }
            }
        }

    def _load_decision_rules(self) -> List[Dict]:
        """Rules for intelligent tool selection based on context - OS aware."""
        return [
            {
                'condition': 'target_type == "ip" and scan_type in ["auto", "network"]',
                'action': 'start_with_nmap',
                'priority': 1,
                'explanation': 'IP addresses require network reconnaissance first to identify services',
                'os_specific': False
            },
            {
                'condition': 'target_type == "url" and scan_type in ["auto", "web"]', 
                'action': 'start_with_web_tools',
                'priority': 1,
                'explanation': 'URLs indicate web applications that need web-specific security testing',
                'os_specific': False
            },
            {
                'condition': 'open_ports contains [80, 443, 8080, 8443]',
                'action': 'follow_up_with_web_scanning',
                'priority': 2,
                'explanation': 'Open web ports suggest web services that need vulnerability assessment',
                'os_specific': False
            },
            {
                'condition': 'target_type == "file"',
                'action': 'use_file_analysis_tools',
                'priority': 1,
                'explanation': 'Files need malware scanning and content analysis',
                'os_specific': True,
                'os_variations': {
                    'windows': 'Use Windows Defender or ClamAV for Windows',
                    'linux': 'Use ClamAV or built-in security tools',
                    'darwin': 'Use ClamAV or macOS built-in XProtect'
                }
            }
        ]

    def analyze_target(self, target: str, scan_type: str = 'auto') -> Dict[str, Any]:
        """
        Analyze target to determine optimal scanning strategy - cross-platform compatible.

        Args:
            target: IP, URL, domain, or file path to analyze
            scan_type: Requested scan type or 'auto' for intelligent selection

        Returns:
            Dictionary containing analysis results and tool recommendations
        """
        analysis = {
            'target': target,
            'target_type': self._classify_target(target),
            'scan_strategy': scan_type,
            'recommended_tools': [],
            'reasoning': [],
            'learning_objectives': [],
            'os_info': {
                'current_os': self.current_os,
                'available_tools': {tool: bool(path) for tool, path in self.tool_paths.items()}
            }
        }

        # Cross-platform target analysis
        if analysis['target_type'] == 'ip':
            if self.tool_paths.get('nmap'):
                analysis['recommended_tools'].append({
                    'name': 'nmap',
                    'phase': 'reconnaissance', 
                    'executable_path': self.tool_paths['nmap'],
                    'options': self._get_nmap_options_for_os(),
                    'learning_objective': 'Understanding network reconnaissance and port scanning'
                })
                analysis['reasoning'].append(
                    f"Starting with Nmap for IP targets on {self.current_os.title()} to discover open ports and running services"
                )
            else:
                analysis['reasoning'].append(
                    f"Nmap not detected on {self.current_os.title()}. "
                    f"Install with: {self.tool_capabilities['nmap']['install_commands'].get(self.current_os, 'Check documentation')}"
                )

        elif analysis['target_type'] in ['url', 'domain']:
            # Cross-platform URL/domain analysis
            if analysis['target_type'] == 'url':
                parsed = urllib.parse.urlparse(target)
                host = parsed.hostname

                # Network scan first (if nmap available)
                if self.tool_paths.get('nmap'):
                    analysis['recommended_tools'].append({
                        'name': 'nmap',
                        'phase': 'reconnaissance',
                        'target_override': host,
                        'executable_path': self.tool_paths['nmap'],
                        'options': self._get_nmap_web_options_for_os(),
                        'learning_objective': 'Identifying web services and potential attack vectors'
                    })

                # Web scan second (if nikto available)
                if self.tool_paths.get('nikto'):
                    analysis['recommended_tools'].append({
                        'name': 'nikto',
                        'phase': 'web_analysis',
                        'executable_path': self.tool_paths['nikto'],
                        'options': self._get_nikto_options_for_os(),
                        'learning_objective': 'Web vulnerability identification and server analysis'
                    })

            analysis['reasoning'].append(
                f"Web targets on {self.current_os.title()} require both network-level and application-level security assessment"
            )

        elif analysis['target_type'] == 'file':
            # Cross-platform file analysis
            file_path = Path(target).resolve()  # Cross-platform path resolution
            
            if self.tool_paths.get('clamscan'):
                analysis['recommended_tools'].append({
                    'name': 'clamav',
                    'phase': 'file_analysis',
                    'executable_path': self.tool_paths['clamscan'],
                    'options': self._get_clamav_options_for_os(),
                    'learning_objective': 'File-based threat detection and malware analysis',
                    'target_path': str(file_path)
                })
            else:
                # Suggest OS-specific alternatives
                alternatives = {
                    'windows': 'Windows Defender (built-in) or download ClamAV for Windows',
                    'linux': 'Install ClamAV: sudo apt install clamav',
                    'darwin': 'Install ClamAV: brew install clamav, or use built-in XProtect'
                }
                analysis['reasoning'].append(
                    f"ClamAV not detected. Alternative for {self.current_os.title()}: "
                    f"{alternatives.get(self.current_os, 'Check documentation')}"
                )

        # Add learning objectives based on selected tools
        for tool in analysis['recommended_tools']:
            tool_info = self.tool_capabilities.get(tool['name'], {})
            analysis['learning_objectives'].append(tool_info.get('learning_value', ''))

        return analysis

    def _classify_target(self, target: str) -> str:
        """Classify the target type - cross-platform compatible."""
        # Check if it's a file path (works on all OS)
        target_path = Path(target)
        
        # Handle different path formats
        if (target_path.exists() or 
            target.startswith('.') or 
            (self.current_os == 'windows' and len(target) > 1 and target[1] == ':') or
            (self.current_os != 'windows' and target.startswith('/'))):
            return 'file'

        # Check if it's a URL
        if target.startswith(('http://', 'https://', 'ftp://')):
            return 'url'

        # Check if it's an IP address
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, target):
            try:
                socket.inet_aton(target)
                return 'ip'
            except (socket.error, OSError):
                pass

        # Check if it's a domain name
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-._]*[a-zA-Z0-9]$'
        if re.match(domain_pattern, target) and '.' in target:
            return 'domain'

        return 'unknown'

    def _get_nmap_options_for_os(self) -> Dict[str, Any]:
        """Get OS-specific Nmap options."""
        base_options = {
            'scan_type': 'syn_scan',
            'port_range': 'top_1000',
            'service_detection': True
        }

        if self.current_os == 'windows':
            # Windows might need different timing or privileges
            base_options['timing'] = 'T3'  # More conservative timing
            base_options['privileged_scan'] = False  # May not have raw socket access
        elif self.current_os == 'linux':
            # Linux typically has better raw socket support
            base_options['timing'] = 'T4'
            base_options['privileged_scan'] = True
        elif self.current_os == 'darwin':
            # macOS similar to Linux but might need sudo
            base_options['timing'] = 'T3'
            base_options['privileged_scan'] = True

        return base_options

    def _get_nmap_web_options_for_os(self) -> Dict[str, Any]:
        """Get OS-specific Nmap options for web scanning."""
        base_options = {
            'scan_type': 'syn_scan',
            'port_range': 'web_ports',
            'service_detection': True,
            'script_scan': True
        }

        # Add OS-specific adjustments
        if self.current_os == 'windows':
            base_options['timing'] = 'T3'
        else:
            base_options['timing'] = 'T4'

        return base_options

    def _get_nikto_options_for_os(self) -> Dict[str, Any]:
        """Get OS-specific Nikto options."""
        base_options = {
            'comprehensive_scan': True,
            'check_outdated': True,
            'test_common_files': True
        }

        if self.current_os == 'windows':
            # On Windows, Nikto runs through Perl
            base_options['perl_path'] = shutil.which('perl')
            base_options['requires_perl'] = True
        else:
            base_options['requires_perl'] = False

        return base_options

    def _get_clamav_options_for_os(self) -> Dict[str, Any]:
        """Get OS-specific ClamAV options."""
        base_options = {
            'scan_archives': True,
            'heuristic_scan': True,
            'update_signatures': True
        }

        if self.current_os == 'windows':
            # Windows ClamAV might have different executable name
            base_options['executable'] = 'clamscan.exe'
            base_options['config_path'] = Path(os.environ.get('PROGRAMFILES', 'C:\\Program Files')) / 'ClamAV'
        elif self.current_os == 'linux':
            base_options['executable'] = 'clamscan'
            base_options['config_path'] = Path('/etc/clamav')
        elif self.current_os == 'darwin':
            base_options['executable'] = 'clamscan'
            base_options['config_path'] = Path('/usr/local/etc/clamav')

        return base_options

    def correlate_results(self, results: Dict[str, Any]) -> List[Dict]:
        """
        Analyze scan results and recommend next actions - cross-platform compatible.
        """
        recommendations = []

        # Analyze Nmap results (same logic across platforms)
        if 'nmap' in results and results['nmap']['success']:
            nmap_data = results['nmap']['data']
            web_ports = [80, 443, 8080, 8443]
            open_web_ports = [port for port in nmap_data.get('open_ports', []) 
                            if port in web_ports]

            if open_web_ports and 'nikto' not in results:
                # Adjust command based on OS
                command_template = self._get_command_template_for_os()
                
                recommendations.append({
                    'action': 'Run web vulnerability scan with Nikto',
                    'tool': 'nikto',
                    'priority': 'high',
                    'reason': f'Found open web ports {open_web_ports} that need security assessment',
                    'command': command_template.format(scan_type='web'),
                    'learning_note': 'Web services are common attack vectors and require specialized scanning',
                    'os_note': f'Running on {self.current_os.title()}'
                })

            # SSH detection (cross-platform)
            if 22 in nmap_data.get('open_ports', []):
                recommendations.append({
                    'action': 'Consider SSH security assessment',
                    'tool': 'ssh_audit',
                    'priority': 'medium', 
                    'reason': 'SSH service detected - check for weak configurations',
                    'command': 'Manual SSH configuration review recommended',
                    'learning_note': 'SSH is critical for remote access security',
                    'os_note': f'SSH security practices apply across all platforms'
                })

        # Sort recommendations by priority
        priority_order = {'high': 1, 'medium': 2, 'low': 3}
        recommendations.sort(key=lambda x: priority_order.get(x['priority'], 4))

        return recommendations

    def _get_command_template_for_os(self) -> str:
        """Get OS-appropriate command template."""
        if self.current_os == 'windows':
            return 'python secops.py scan <target> --type {scan_type}'
        else:
            return './secops.py scan <target> --type {scan_type}'

    def check_tool_availability(self) -> Dict[str, Dict[str, Any]]:
        """Check which tools are available on the current system."""
        availability = {}
        
        for tool_name, tool_info in self.tool_capabilities.items():
            executable_name = tool_name
            if self.current_os == 'windows' and tool_name == 'clamav':
                executable_name = 'clamscan'
            
            tool_path = self.tool_paths.get(tool_name) or self.tool_paths.get(executable_name)
            
            availability[tool_name] = {
                'available': bool(tool_path),
                'path': tool_path,
                'install_command': tool_info['install_commands'].get(self.current_os, 'Unknown'),
                'cross_platform': tool_info.get('cross_platform', False)
            }
        
        return availability

    def get_os_specific_recommendations(self) -> List[str]:
        """Provide OS-specific security recommendations."""
        recommendations = []
        
        if self.current_os == 'windows':
            recommendations.extend([
                "Consider running Command Prompt as Administrator for advanced scans",
                "Windows Defender provides basic protection - ClamAV adds cross-platform compatibility",
                "Some tools may require additional permissions or specific versions for Windows"
            ])
        elif self.current_os == 'linux':
            recommendations.extend([
                "Most security tools work natively on Linux with full feature support",
                "Use package managers (apt, yum, dnf) for easy tool installation",
                "Consider running scans with appropriate privileges (sudo when needed)"
            ])
        elif self.current_os == 'darwin':
            recommendations.extend([
                "Homebrew provides easy installation for most security tools on macOS",
                "Some tools may require Xcode command line tools to be installed",
                "macOS security features may require additional permissions for some scans"
            ])
        
        return recommendations

    def deep_analysis(self, scan_data: Dict[str, Any]) -> List[str]:
        """Perform deep analysis on scan results - enhanced with OS awareness."""
        insights = []

        # Add OS-specific context to analysis
        insights.append(f"Analysis performed on {self.current_os.title()} platform")

        if 'scan_results' in scan_data:
            results = scan_data['scan_results']

            # Analyze patterns in the data
            total_ports = sum(len(result.get('open_ports', [])) 
                            for result in results.values() 
                            if 'open_ports' in result)

            if total_ports > 10:
                insights.append(
                    f"Large attack surface detected: {total_ports} open ports found. "
                    "Consider implementing network segmentation and port filtering."
                )

            # OS-specific security insights
            os_insights = self._get_os_security_insights(results)
            insights.extend(os_insights)

        return insights

    def _get_os_security_insights(self, results: Dict[str, Any]) -> List[str]:
        """Get OS-specific security insights."""
        insights = []
        
        if self.current_os == 'windows':
            insights.append(
                "Windows environments should consider Windows Update status and "
                "PowerShell execution policies in security assessments"
            )
        elif self.current_os == 'linux':
            insights.append(
                "Linux systems should review service configurations, user permissions, "
                "and package update status as part of security analysis"
            )
        elif self.current_os == 'darwin':
            insights.append(
                "macOS security should include Gatekeeper status, System Integrity Protection, "
                "and application permissions in comprehensive assessments"
            )
        
        return insights
