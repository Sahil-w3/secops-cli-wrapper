#!/usr/bin/env python3
"""
SecOps CLI Wrapper - Cross-Platform Intelligent Cybersecurity Automation Tool
A beginner-friendly CLI that dynamically selects and orchestrates security tools
while teaching cybersecurity concepts on Windows, Linux, and macOS.

Author: Silicon Valley Cybersecurity Scientist
Compatible with: Windows 10+, Linux (Ubuntu/Debian/RHEL), macOS 10.15+
"""

import click
import json
import subprocess
import sys
import platform
import shutil
from datetime import datetime
from pathlib import Path
import os

# Import our custom modules
try:
    from decision_engine import DecisionEngine  
    from tool_wrappers import ToolManager
    from learning_engine import LearningSystem
except ImportError as e:
    click.echo(f"❌ Error importing modules: {e}")
    click.echo("Make sure all required files are in the same directory:")
    click.echo("  - decision_engine.py")
    click.echo("  - tool_wrappers.py") 
    click.echo("  - learning_engine.py")
    sys.exit(1)

class SecOpsCLI:
    def __init__(self):
        # Detect current operating system
        self.current_os = platform.system().lower()  # 'windows', 'linux', 'darwin'
        self.os_version = platform.version()
        self.python_version = platform.python_version()
        
        # Initialize core components with OS awareness
        try:
            self.decision_engine = DecisionEngine()
            self.tool_manager = ToolManager()
            self.learning_system = LearningSystem()
        except Exception as e:
            click.echo(f"❌ Error initializing components: {e}")
            sys.exit(1)
            
        self.session_log = []
        self.config_path = self._get_config_path()
        
        # OS-specific settings
        self.os_settings = self._load_os_settings()

    def _get_config_path(self) -> Path:
        """Get OS-appropriate configuration directory."""
        if self.current_os == 'windows':
            # Windows: Use AppData
            config_dir = Path(os.environ.get('APPDATA', '')) / 'SecOpsCLI'
        elif self.current_os == 'darwin':
            # macOS: Use Application Support
            config_dir = Path.home() / 'Library' / 'Application Support' / 'SecOpsCLI'
        else:
            # Linux: Use XDG config directory
            xdg_config = os.environ.get('XDG_CONFIG_HOME', str(Path.home() / '.config'))
            config_dir = Path(xdg_config) / 'secops-cli'
        
        # Create directory if it doesn't exist
        config_dir.mkdir(parents=True, exist_ok=True)
        return config_dir / 'config.json'

    def _load_os_settings(self) -> dict:
        """Load OS-specific settings and capabilities."""
        settings = {
            'windows': {
                'shell': ['cmd', '/c'],
                'shell_script_ext': '.bat',
                'executable_ext': '.exe',
                'path_separator': ';',
                'admin_required_msg': 'Some scans may require running as Administrator',
                'common_tool_paths': [
                    r'C:\Program Files\Nmap',
                    r'C:\Program Files (x86)\Nmap',
                    r'C:\Program Files\ClamAV',
                    r'C:\Program Files (x86)\ClamAV'
                ]
            },
            'linux': {
                'shell': ['/bin/bash', '-c'],
                'shell_script_ext': '.sh',
                'executable_ext': '',
                'path_separator': ':',
                'admin_required_msg': 'Some scans may require sudo privileges',
                'common_tool_paths': [
                    '/usr/bin',
                    '/usr/local/bin',
                    '/opt'
                ]
            },
            'darwin': {
                'shell': ['/bin/bash', '-c'],
                'shell_script_ext': '.sh', 
                'executable_ext': '',
                'path_separator': ':',
                'admin_required_msg': 'Some scans may require sudo privileges',
                'common_tool_paths': [
                    '/usr/bin',
                    '/usr/local/bin',
                    '/opt/homebrew/bin',
                    '/usr/local/Cellar'
                ]
            }
        }
        return settings.get(self.current_os, settings['linux'])

    def log_action(self, action: str, result=None, explanation=None):
        """Log all actions for learning and audit purposes with OS context."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "result": result,
            "explanation": explanation,
            "os": self.current_os,
            "os_version": self.os_version,
            "python_version": self.python_version
        }
        self.session_log.append(log_entry)

    def save_session_log(self, filename: str = None):
        """Save session log to file with OS-appropriate path."""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"secops_session_{timestamp}.json"
        
        log_path = self.config_path.parent / filename
        
        try:
            with open(log_path, 'w') as f:
                json.dump(self.session_log, f, indent=2)
            return str(log_path)
        except Exception as e:
            click.echo(f"⚠️  Warning: Could not save session log: {e}")
            return None

    def check_system_requirements(self) -> dict:
        """Check system requirements and tool availability."""
        requirements = {
            'python_version_ok': sys.version_info >= (3, 7),
            'os_supported': self.current_os in ['windows', 'linux', 'darwin'],
            'tools_available': [],
            'missing_tools': [],
            'warnings': []
        }

        # Check Python version
        if not requirements['python_version_ok']:
            requirements['warnings'].append(
                f"Python {sys.version} detected. Python 3.7+ recommended."
            )

        # Check for security tools
        common_tools = ['nmap', 'nikto', 'clamscan']
        for tool in common_tools:
            if self.current_os == 'windows' and tool != 'nmap':
                # On Windows, some tools have .exe extension or different names
                tool_variants = [tool, f"{tool}.exe", f"{tool}.pl"]
            else:
                tool_variants = [tool]
            
            found = False
            for variant in tool_variants:
                if shutil.which(variant):
                    requirements['tools_available'].append(tool)
                    found = True
                    break
            
            if not found:
                requirements['missing_tools'].append(tool)

        return requirements

# Initialize CLI instance
cli_instance = SecOpsCLI()

@click.group(invoke_without_command=True)
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--learn', is_flag=True, help='Enable learning mode with explanations')
@click.option('--os-info', is_flag=True, help='Show OS and system information')
@click.pass_context
def secops(ctx, verbose, learn, os_info):
    """
    SecOps CLI - Cross-Platform Intelligent Cybersecurity Automation with Learning

    This tool intelligently selects and runs security tools based on your targets
    and scan results, while teaching you cybersecurity concepts along the way.
    
    Supported Platforms: Windows 10+, Linux (Ubuntu/Debian/RHEL), macOS 10.15+
    """
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    ctx.obj['learn'] = learn

    if os_info:
        click.echo(f"🖥️  System Information:")
        click.echo(f"   Operating System: {platform.system()} {platform.release()}")
        click.echo(f"   Python Version: {platform.python_version()}")
        click.echo(f"   Architecture: {platform.machine()}")
        click.echo(f"   Processor: {platform.processor()}")
        return

    if ctx.invoked_subcommand is None:
        # Show welcome message with OS-specific context
        click.echo("🚀 Welcome to SecOps CLI - Your Cross-Platform Security Assistant!")
        click.echo(f"📱 Running on: {cli_instance.current_os.title()}")
        
        if cli_instance.current_os == 'windows':
            click.echo("💡 Windows users: Consider running as Administrator for full functionality")
        elif cli_instance.current_os in ['linux', 'darwin']:
            click.echo("💡 Unix users: Some commands may require sudo privileges")
        
        click.echo("\nUse 'secops --help' to see all available commands.")
        click.echo("Use 'secops config --check-dependencies' to verify tool installation.")
        
        if learn:
            cli_instance.learning_system.show_intro()

@secops.command()
@click.argument('target')
@click.option('--type', 'scan_type', 
              type=click.Choice(['auto', 'network', 'web', 'file', 'comprehensive']),
              default='auto',
              help='Type of scan to perform')
@click.option('--intensity', type=click.IntRange(1, 5), default=3,
              help='Scan intensity level (1=basic, 5=thorough)')
@click.option('--output', '-o', type=click.Path(), 
              help='Save results to file (auto-detects format from extension)')
@click.pass_context
def scan(ctx, target, scan_type, intensity, output):
    """
    Intelligently scan a target and recommend next actions.

    TARGET can be an IP address, URL, domain name, or file path.
    The tool will automatically determine the best scanning approach for your OS.
    
    Examples:
      secops scan 192.168.1.1 --learn
      secops scan https://example.com --type web --intensity 4
      secops scan suspicious_file.exe --type file
    """
    click.echo(f"🔍 Starting intelligent scan of: {target}")
    click.echo(f"🖥️  Platform: {cli_instance.current_os.title()}")
    
    # Show OS-specific advisory if needed
    if ctx.obj['verbose']:
        click.echo(f"ℹ️  {cli_instance.os_settings['admin_required_msg']}")

    try:
        # Step 1: Analyze target and determine optimal tools
        analysis = cli_instance.decision_engine.analyze_target(target, scan_type)

        if ctx.obj['learn']:
            cli_instance.learning_system.explain_target_analysis(analysis)

        # Step 2: Check if required tools are available on this OS
        missing_tools = []
        for tool_config in analysis['recommended_tools']:
            tool_name = tool_config['name']
            if not cli_instance.tool_manager.is_tool_available(tool_name):
                missing_tools.append(tool_name)

        if missing_tools:
            click.echo(f"⚠️  Missing tools on {cli_instance.current_os.title()}: {', '.join(missing_tools)}")
            click.echo("Use 'secops config --check-dependencies' for installation instructions.")

        # Step 3: Execute available tools in sequence
        results = {}
        for tool_config in analysis['recommended_tools']:
            tool_name = tool_config['name']
            
            if tool_name in missing_tools:
                results[tool_name] = {
                    'success': False,
                    'error': f"Tool not available on {cli_instance.current_os}",
                    'summary': 'Tool not installed'
                }
                continue

            if ctx.obj['verbose']:
                click.echo(f"🔧 Running {tool_name} on {cli_instance.current_os.title()}...")

            # Add OS-specific options to tool configuration
            tool_config['options'].update({
                'os': cli_instance.current_os,
                'shell_settings': cli_instance.os_settings
            })

            tool_result = cli_instance.tool_manager.execute_tool(
                tool_name, 
                target, 
                tool_config['options']
            )
            results[tool_name] = tool_result

            if ctx.obj['learn']:
                cli_instance.learning_system.explain_tool_purpose(tool_name, tool_result)

        # Step 4: Correlate results and suggest next actions
        recommendations = cli_instance.decision_engine.correlate_results(results)

        # Step 5: Display results with OS context
        click.echo("\n📊 Scan Results Summary:")
        for tool, result in results.items():
            if result['success']:
                status = "✅ Complete"
                summary = result.get('summary', 'Scan completed successfully')
            else:
                status = "❌ Failed" 
                summary = result.get('error', result.get('summary', 'Unknown error'))
            
            click.echo(f"  {tool}: {status} - {summary}")

        click.echo("\n🎯 Recommended Next Actions:")
        if recommendations:
            for i, rec in enumerate(recommendations, 1):
                priority_icon = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(rec['priority'], "⚪")
                click.echo(f"  {i}. {priority_icon} {rec['action']}")
                click.echo(f"     Reason: {rec['reason']}")
                if 'os_note' in rec:
                    click.echo(f"     Platform note: {rec['os_note']}")
        else:
            click.echo("  No additional actions recommended at this time.")

        # Step 6: Save results if requested
        scan_data = {
            "target": target,
            "scan_type": scan_type,
            "intensity": intensity,
            "platform": cli_instance.current_os,
            "timestamp": datetime.now().isoformat(),
            "results": results,
            "recommendations": recommendations
        }

        if output:
            output_path = Path(output)
            try:
                with open(output_path, 'w') as f:
                    json.dump(scan_data, f, indent=2)
                click.echo(f"💾 Results saved to: {output_path.absolute()}")
            except Exception as e:
                click.echo(f"⚠️  Could not save to {output}: {e}")

        # Log the session
        cli_instance.log_action("scan", scan_data)

    except KeyboardInterrupt:
        click.echo("\n⏹️  Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        click.echo(f"❌ Scan failed: {e}")
        if ctx.obj['verbose']:
            import traceback
            click.echo(traceback.format_exc())
        sys.exit(1)

@secops.command()
@click.argument('scan_results', type=click.Path(exists=True))
@click.pass_context  
def analyze(ctx, scan_results):
    """
    Analyze previous scan results and provide deeper insights.

    SCAN_RESULTS should be a JSON file from a previous scan.
    Works with scan files from any supported platform.
    """
    click.echo(f"📈 Analyzing scan results from: {scan_results}")

    try:
        with open(scan_results, 'r') as f:
            data = json.load(f)

        # Show source platform info if available
        source_platform = data.get('platform', 'unknown')
        if source_platform != cli_instance.current_os:
            click.echo(f"ℹ️  Note: Results from {source_platform}, analyzing on {cli_instance.current_os}")

        insights = cli_instance.decision_engine.deep_analysis(data)

        if ctx.obj['learn']:
            cli_instance.learning_system.explain_analysis_techniques(insights)

        click.echo("\n🔬 Deep Analysis Results:")
        for insight in insights:
            click.echo(f"  • {insight}")

        # Get OS-specific recommendations
        os_recommendations = cli_instance.decision_engine.get_os_specific_recommendations()
        if os_recommendations:
            click.echo(f"\n🛡️  Security Recommendations for {cli_instance.current_os.title()}:")
            for rec in os_recommendations:
                click.echo(f"  • {rec}")

    except json.JSONDecodeError:
        click.echo("❌ Invalid JSON file format")
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Analysis failed: {e}")
        sys.exit(1)

@secops.command()
@click.option('--topic', type=click.Choice(['scanning', 'vulnerabilities', 'tools', 'methodology']),
              help='Focus learning on a specific topic')
@click.pass_context
def learn(ctx, topic):
    """
    Interactive learning mode for cybersecurity concepts.

    Learn about security tools, methodologies, and best practices
    with platform-specific guidance and examples.
    """
    click.echo(f"🎓 Welcome to SecOps Learning Mode on {cli_instance.current_os.title()}!")

    if topic:
        cli_instance.learning_system.focused_learning(topic)
    else:
        cli_instance.learning_system.interactive_menu()

@secops.command()
@click.option('--list-tools', is_flag=True, help='List all available security tools')
@click.option('--check-dependencies', is_flag=True, help='Check if required tools are installed')
@click.option('--install-guide', is_flag=True, help='Show OS-specific installation guide')
@click.option('--system-info', is_flag=True, help='Show detailed system information')
@click.pass_context
def config(ctx, list_tools, check_dependencies, install_guide, system_info):
    """
    Configure and manage security tools and settings across platforms.
    """
    
    if system_info:
        requirements = cli_instance.check_system_requirements()
        click.echo(f"🖥️  System Information:")
        click.echo(f"   OS: {platform.system()} {platform.release()}")
        click.echo(f"   Architecture: {platform.machine()}")
        click.echo(f"   Python: {platform.python_version()}")
        click.echo(f"   Python OK: {'✅' if requirements['python_version_ok'] else '❌'}")
        click.echo(f"   OS Supported: {'✅' if requirements['os_supported'] else '❌'}")
        
        if requirements['warnings']:
            click.echo(f"\n⚠️  Warnings:")
            for warning in requirements['warnings']:
                click.echo(f"   • {warning}")

    if list_tools:
        availability = cli_instance.decision_engine.check_tool_availability()
        click.echo(f"🔧 Security Tools Status on {cli_instance.current_os.title()}:")
        
        for tool_name, info in availability.items():
            status = "✅" if info['available'] else "❌"
            path_info = f" ({info['path']})" if info['path'] else ""
            click.echo(f"  {status} {tool_name}{path_info}")
            
            if not info['available'] and ctx.obj.get('verbose'):
                click.echo(f"      Install: {info['install_command']}")

    if check_dependencies:
        click.echo(f"🔍 Checking dependencies on {cli_instance.current_os.title()}...")
        requirements = cli_instance.check_system_requirements()
        
        click.echo("\n📦 Available Tools:")
        for tool in requirements['tools_available']:
            click.echo(f"  ✅ {tool}")
        
        if requirements['missing_tools']:
            click.echo("\n❌ Missing Tools:")
            for tool in requirements['missing_tools']:
                click.echo(f"  ❌ {tool}")
        
        if requirements['missing_tools']:
            click.echo(f"\n💡 Use 'secops config --install-guide' for installation instructions.")

    if install_guide:
        click.echo(f"📋 Installation Guide for {cli_instance.current_os.title()}:")
        
        if cli_instance.current_os == 'windows':
            click.echo("\n🪟 Windows Installation:")
            click.echo("  1. Nmap: Download from https://nmap.org/download.html")
            click.echo("  2. Nikto: Install Strawberry Perl, then download Nikto from GitHub")
            click.echo("  3. ClamAV: Download from https://www.clamav.net/downloads")
            click.echo("\n💡 Tip: Run PowerShell as Administrator for installations")
        
        elif cli_instance.current_os == 'linux':
            click.echo("\n🐧 Linux Installation:")
            click.echo("  Ubuntu/Debian:")
            click.echo("    sudo apt update")
            click.echo("    sudo apt install nmap nikto clamav")
            click.echo("  RHEL/CentOS/Fedora:")
            click.echo("    sudo yum install nmap nikto clamav")
            click.echo("    # or sudo dnf install nmap nikto clamav")
        
        elif cli_instance.current_os == 'darwin':
            click.echo("\n🍎 macOS Installation:")
            click.echo("  Using Homebrew (recommended):")
            click.echo("    brew install nmap nikto clamav")
            click.echo("  Manual downloads:")
            click.echo("    Nmap: https://nmap.org/download.html")
            click.echo("    Others: Follow Linux instructions or compile from source")

@secops.command()
@click.option('--save', is_flag=True, help='Save current session log')
@click.option('--clear', is_flag=True, help='Clear session log')
@click.pass_context
def session(ctx, save, clear):
    """
    Manage session logs and history.
    """
    if save:
        log_path = cli_instance.save_session_log()
        if log_path:
            click.echo(f"💾 Session log saved to: {log_path}")
        else:
            click.echo("❌ Failed to save session log")
    
    if clear:
        cli_instance.session_log.clear()
        click.echo("🗑️  Session log cleared")
    
    if not save and not clear:
        click.echo(f"📜 Current session: {len(cli_instance.session_log)} actions logged")
        if cli_instance.session_log:
            click.echo("Recent actions:")
            for entry in cli_instance.session_log[-5:]:  # Show last 5 actions
                timestamp = entry['timestamp'][:19]  # Remove microseconds
                click.echo(f"  {timestamp}: {entry['action']}")

if __name__ == '__main__':
    try:
        secops()
    except KeyboardInterrupt:
        click.echo("\n👋 SecOps CLI interrupted. Goodbye!")
        sys.exit(0)
    except Exception as e:
        click.echo(f"💥 Unexpected error: {e}")
        sys.exit(1)
