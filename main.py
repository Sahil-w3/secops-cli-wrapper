#!/usr/bin/env python3
"""
SecOps CLI Wrapper – Cross-Platform Intelligent Cyber-Security Automation Tool
A beginner-friendly CLI that dynamically selects and orchestrates tools
while teaching cyber-security concepts on Windows, Linux and macOS.

Author   :  Silicon Valley Cyber-Security Scientist  
Compatible with :  Windows 10 +  (Ubuntu / Debian / RHEL) ,  macOS 10.15 +
"""

# ------------------------------------------------------------
#  Standard-library / third-party imports
# ------------------------------------------------------------
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import click            # ← Correct import (no smart spaces / duplicates)

# ------------------------------------------------------------
#  Local modules (must live in the same folder)
# ------------------------------------------------------------
try:
    from decision_engine import DecisionEngine
    from tool_wrappers   import ToolManager
    from learning_engine import LearningSystem
except ImportError as err:
    click.echo(f"❌  Import error: {err}")
    click.echo("Ensure decision_engine.py, tool_wrappers.py and learning_engine.py "
               "are in the same directory as main.py")
    sys.exit(1)

# ------------------------------------------------------------
#  Wrapper class
# ------------------------------------------------------------
class SecOpsCLI:
    def __init__(self) -> None:
        # Detect host OS
        self.current_os     = platform.system().lower()          # windows / linux / darwin
        self.os_version     = platform.version()
        self.python_version = platform.python_version()

        # Core engines
        try:
            self.decision_engine = DecisionEngine()
            self.tool_manager    = ToolManager()
            self.learning_system = LearningSystem()
        except Exception as exc:
            click.echo(f"❌  Failed initialising components: {exc}")
            sys.exit(1)

        # Session state
        self.session_log: list = []

        # Config-file path
        self.config_path: Path = self._get_config_path()

        # Per-OS helpers
        self.os_settings: dict = self._load_os_settings()

    # --------------------------------------------------------
    #  Helpers
    # --------------------------------------------------------
    def _get_config_path(self) -> Path:
        """Return platform-appropriate config directory / file."""
        if self.current_os == "windows":
            root = Path(os.getenv("APPDATA", "")) / "SecOpsCLI"
        elif self.current_os == "darwin":
            root = Path.home() / "Library" / "Application Support" / "SecOpsCLI"
        else:                                      # linux
            root = Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config")) / "secops-cli"

        root.mkdir(parents=True, exist_ok=True)
        return root / "config.json"

    def _load_os_settings(self) -> dict:
        return {
            "windows": {
                "shell": ["cmd", "/c"],
                "admin_hint": "Run PowerShell as Administrator for full functionality",
            },
            "linux": {
                "shell": ["/bin/bash", "-c"],
                "admin_hint": "Some commands may need sudo privileges",
            },
            "darwin": {
                "shell": ["/bin/bash", "-c"],
                "admin_hint": "Some commands may need sudo privileges",
            },
        }[self.current_os]

    def log_action(self, action: str, payload: dict | None = None) -> None:
        self.session_log.append(
            {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "action": action,
                "payload": payload,
                "platform": self.current_os,
            }
        )

    def save_session(self, fn: str | None = None) -> str | None:
        out = Path(fn) if fn else (self.config_path.parent / f"session_{int(datetime.utcnow().timestamp())}.json")
        try:
            out.write_text(json.dumps(self.session_log, indent=2), encoding="utf-8")
            return str(out)
        except Exception as exc:
            click.echo(f"⚠️  Could not save session log: {exc}")
            return None

# ------------------------------------------------------------
#  Click CLI root
# ------------------------------------------------------------
cli = SecOpsCLI()

@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Show verbose output")
@click.option("--learn",    is_flag=True, help="Enable learning mode")
@click.option("--os-info",  is_flag=True, help="Show host OS information and exit")
@click.pass_context
def secops(ctx: click.Context, verbose: bool, learn: bool, os_info: bool) -> None:
    """SecOps CLI – intelligent, cross-platform cyber-security assistant."""
    ctx.obj = {"verbose": verbose, "learn": learn}

    if os_info:
        click.echo(f"OS           : {platform.system()} {platform.release()}")
        click.echo(f"Python       : {platform.python_version()}")
        click.echo(f"Architecture : {platform.machine()}")
        sys.exit(0)

    if ctx.invoked_subcommand is None:
        click.echo("🚀  SecOps CLI ready.  Use  secops --help  for commands.")

# ------------------------------------------------------------
#  SCAN command
# ------------------------------------------------------------
@secops.command()
@click.argument("target")
@click.option("--type",    "stype", default="auto",
              type=click.Choice(["auto", "network", "web", "file"]), show_default=True)
@click.option("--output", "-o", type=click.Path(), help="Save scan JSON to file")
@click.pass_context
def scan(ctx: click.Context, target: str, stype: str, output: str | None) -> None:
    """Smart scan a TARGET (IP / URL / file) and recommend next steps."""
    verbose, learn = ctx.obj["verbose"], ctx.obj["learn"]

    click.echo(f"🔍  Scanning {target} ({stype}) on {cli.current_os.title()}")

    analysis = cli.decision_engine.analyze_target(target, stype)
    if learn:
        cli.learning_system.explain_target_analysis(analysis)

    missing = [t["name"] for t in analysis["recommended_tools"] if not cli.tool_manager.is_tool_available(t["name"])]
    if missing:
        click.echo(f"⚠️  Missing tools: {', '.join(missing)}")

    results = {}
    for tool in analysis["recommended_tools"]:
        name = tool["name"]
        if name in missing:
            results[name] = {"success": False, "summary": "Tool not installed"}
            continue
        if verbose:
            click.echo(f"→ {name} …")
        res = cli.tool_manager.execute_tool(name, target, tool["options"])
        results[name] = res
        if learn:
            cli.learning_system.explain_tool_purpose(name, res)

    recs = cli.decision_engine.correlate_results(results)

    click.echo("\n📊  Summary")
    for k, v in results.items():
        status = "✅" if v["success"] else "❌"
        click.echo(f"  {status} {k}: {v['summary']}")

    if recs:
        click.echo("\n🎯  Recommendations")
        for r in recs:
            click.echo(f" • {r['action']}  –  {r['reason']}")

    if output:
        Path(output).write_text(json.dumps({"results": results, "recommendations": recs}, indent=2))
        click.echo(f"\n💾  Saved to {output}")

    cli.log_action("scan", {"target": target, "results": results})
# ------------------------------------------------------------
#  Other minimal commands (analyze, config, etc.) could follow
# ------------------------------------------------------------

if __name__ == "__main__":
    try:
        secops()
    except KeyboardInterrupt:
        click.echo("\nInterrupted by user.")