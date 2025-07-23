# SecOps CLI Wrapper - Complete Implementation Guide

**Project**: Intelligent Cybersecurity Automation CLI with Learning Integration  
**Target Audience**: Assistant familiar with VSCode, VMware, GitHub  
**Timeline**: 6 weeks  
**Language**: Python with Click framework

## Table of Contents
- [Project Overview](#project-overview)
- [Development Environment Setup](#development-environment-setup)
- [Phase 1: Foundation (Weeks 1-2)](#phase-1-foundation)
- [Phase 2: Intelligence (Weeks 3-4)](#phase-2-intelligence)
- [Phase 3: Learning & Polish (Weeks 5-6)](#phase-3-learning--polish)
- [Testing Strategy](#testing-strategy)
- [Deployment Guide](#deployment-guide)

## Project Overview

### What We're Building
An intelligent CLI wrapper that:
- **Dynamically selects** security tools based on target analysis
- **Orchestrates workflows** by chaining tools intelligently  
- **Explains decisions** with educational context
- **Teaches concepts** while performing security tasks
- **Prioritizes findings** using correlation algorithms

### Architecture Components
```
SecOps-CLI-Wrapper/
├── main.py                 # Click-based CLI interface
├── decision_engine.py      # Intelligent tool selection
├── tool_wrappers.py       # Security tool integrations
├── learning_engine.py     # Educational features
├── config.py              # Configuration management
├── utils.py               # Helper functions
├── requirements.txt       # Python dependencies
├── tests/                 # Test suite
└── docs/                  # Documentation
```

## Development Environment Setup

### Step 1: VMware Environment Preparation

**VM Specifications:**
- **OS**: Ubuntu 22.04 LTS (recommended) or Kali Linux
- **RAM**: Minimum 4GB (8GB recommended)
- **Storage**: 50GB minimum
- **Network**: NAT or Bridged for tool testing

**Initial VM Setup:**
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install essential development tools
sudo apt install -y python3 python3-pip python3-venv git curl wget

# Install security tools that our CLI will integrate
sudo apt install -y nmap nikto clamav john hashcat
```

### Step 2: VSCode Configuration

**Install VSCode Extensions:**
1. **Python** (Microsoft) - Core Python support
2. **Python Debugger** - Debugging support
3. **GitLens** - Git integration
4. **autoDocstring** - Documentation generation
5. **Python Test Explorer** - Test management

**VSCode Settings (settings.json):**
```json
{
    "python.defaultInterpreterPath": "./venv/bin/python",
    "python.linting.enabled": true,
    "python.linting.pylintEnabled": true,
    "python.formatting.provider": "black",
    "python.testing.pytestEnabled": true,
    "files.autoSave": "onFocusChange",
    "terminal.integrated.defaultProfile.linux": "bash"
}
```

### Step 3: GitHub Repository Setup

**Create Repository:**
```bash
# Create project directory
mkdir secops-cli-wrapper
cd secops-cli-wrapper

# Initialize Git
git init
git remote add origin https://github.com/your-username/secops-cli-wrapper.git

# Create initial project structure
mkdir -p tests docs examples
touch main.py decision_engine.py tool_wrappers.py learning_engine.py
touch requirements.txt README.md .gitignore
```

**Initial .gitignore:**
```gitignore
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
venv/
.venv/
.env
.pytest_cache/
.coverage
*.log
*.tmp
.vscode/settings.json
```

### Step 4: Python Environment Setup

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install initial dependencies
pip install click rich colorama requests python-dateutil pytest black pylint

# Create requirements.txt
pip freeze > requirements.txt
```

## Phase 1: Foundation (Weeks 1-2)

### Week 1: Core CLI Framework

**Day 1-2: Click Framework Implementation**

Create the main CLI structure:

```bash
# Install Click and development tools
pip install click rich pytest

# Test the basic CLI structure
python main.py --help
python main.py scan --help
```

**Key Implementation Steps:**

1. **Copy our main.py code** into your project
2. **Test basic commands**:
   ```bash
   python main.py scan 127.0.0.1 --learn
   python main.py config --list-tools
   ```

**Day 3-4: Basic Tool Integration**

Start with Nmap integration:

```python
# In tool_wrappers.py
import subprocess
import json

class ToolManager:
    def execute_nmap(self, target, options):
        """Execute Nmap with educational context."""
        cmd = ['nmap', '-oX', '-']  # XML output to stdout
        
        # Add scan options based on intelligence
        if options.get('service_detection'):
            cmd.append('-sV')
        if options.get('syn_scan'):
            cmd.extend(['-sS'])
        
        cmd.append(target)
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return self._parse_nmap_xml(result.stdout)
        except subprocess.TimeoutExpired:
            return {"error": "Scan timeout", "success": False}
```

**Day 5-7: GitHub Integration & Documentation**

```bash
# Commit initial structure
git add .
git commit -m "Initial CLI framework with Click and basic tool integration"
git push origin main

# Create GitHub Actions for CI/CD
mkdir -p .github/workflows
```

**GitHub Actions Workflow (.github/workflows/test.yml):**
```yaml
name: SecOps CLI Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
    - name: Run tests
      run: pytest tests/ -v
```

### Week 2: Decision Engine Foundation

**Day 8-10: Target Classification Logic**

Implement intelligent target analysis:

```python
# Test target classification
targets = [
    "192.168.1.1",
    "https://example.com", 
    "example.com",
    "/path/to/suspicious/file.exe"
]

for target in targets:
    analysis = decision_engine.analyze_target(target)
    print(f"{target} -> {analysis['target_type']}")
```

**Day 11-14: Basic Learning Integration**

Implement educational explanations:

```bash
# Test learning mode
python main.py scan 127.0.0.1 --learn --verbose
```

**Testing at End of Phase 1:**
```bash
# Functional tests
python main.py scan scanme.nmap.org --type auto --learn
python main.py config --check-dependencies
python main.py learn --topic scanning

# Run test suite
pytest tests/ -v --cov=.
```

## Phase 2: Intelligence (Weeks 3-4)

### Week 3: Advanced Decision Making

**Day 15-17: Result Correlation Engine**

Implement intelligent result analysis:

```python
# Example correlation logic
def correlate_results(self, results):
    recommendations = []
    
    # If Nmap found web ports, recommend web scanning
    if 'nmap' in results:
        web_ports = [80, 443, 8080, 8443]
        found_web = any(port in results['nmap']['open_ports'] for port in web_ports)
        
        if found_web and 'nikto' not in results:
            recommendations.append({
                'action': 'Web vulnerability scan needed',
                'priority': 'high',
                'reasoning': 'Open web ports detected'
            })
    
    return recommendations
```

**Day 18-21: Workflow Orchestration**

Implement sequential tool execution with intelligent decision points:

```python
# Test workflow
python main.py scan targetsite.com --intensity 4 --learn
# Should automatically: Nmap -> Nikto -> Analysis -> Recommendations
```

### Week 4: Tool Integration Expansion

**Day 22-24: Additional Tool Wrappers**

Add support for:
- **Nikto** for web vulnerability scanning
- **ClamAV** for malware detection
- **Basic password strength testing**

**Day 25-28: Output Standardization**

Create uniform output format:

```python
class StandardResult:
    def __init__(self, tool_name, target, success, data, summary):
        self.tool_name = tool_name
        self.target = target
        self.success = success
        self.data = data
        self.summary = summary
        self.timestamp = datetime.now()
```

**Testing at End of Phase 2:**
```bash
# Complex workflow test
python main.py scan testphp.vulnweb.com --comprehensive --learn

# Verify intelligent decision making
python main.py scan 192.168.1.0/24 --type network
```

## Phase 3: Learning & Polish (Weeks 5-6)

### Week 5: Educational Features

**Day 29-31: Interactive Learning Mode**

Implement comprehensive educational features:

```python
# Interactive learning menu
python main.py learn
# Should present menu with:
# 1. Scanning Methodology
# 2. Vulnerability Assessment  
# 3. Tool Selection Guide
# 4. Hands-on Exercises
```

**Day 32-35: User Experience Polish**

Focus on:
- **Colorful output** using Rich library
- **Progress indicators** for long-running scans
- **Clear error messages** with suggested fixes
- **Helpful command suggestions**

### Week 6: Finalization

**Day 36-38: Documentation & Packaging**

Create comprehensive documentation:

```markdown
# docs/user-guide.md
# docs/developer-guide.md  
# docs/tool-integration-guide.md
```

**Day 39-42: Final Testing & Deployment**

```bash
# Package for distribution
python setup.py sdist bdist_wheel

# Install locally and test
pip install -e .
secops --help

# Final integration tests
pytest tests/ --full-coverage
```

## Testing Strategy

### Unit Testing Structure

```python
# tests/test_decision_engine.py
def test_target_classification():
    engine = DecisionEngine()
    
    assert engine._classify_target('192.168.1.1') == 'ip'
    assert engine._classify_target('https://example.com') == 'url'
    assert engine._classify_target('example.com') == 'domain'
```

### Integration Testing

```python
# tests/test_integration.py
def test_full_scan_workflow():
    """Test complete scan workflow with mocked tools."""
    result = subprocess.run(['python', 'main.py', 'scan', '127.0.0.1'], 
                          capture_output=True, text=True)
    assert result.returncode == 0
    assert 'Scan Results Summary' in result.stdout
```

### Testing Tools Installation

```bash
# Create test environment
python tests/setup_test_env.py

# Verify all security tools are available
python tests/test_tool_availability.py
```

## Key Implementation Tips

### 1. Error Handling Best Practices

```python
try:
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
except subprocess.TimeoutExpired:
    return {"error": "Tool execution timeout", "suggestion": "Try reducing scan scope"}
except FileNotFoundError:
    return {"error": "Tool not installed", "suggestion": "Run: apt install toolname"}
```

### 2. Security Considerations

```python
# Input validation
def validate_target(target):
    """Validate and sanitize user input to prevent command injection."""
    if not re.match(r'^[a-zA-Z0-9.-/:_]+$', target):
        raise ValueError("Invalid characters in target")
    return target
```

### 3. Learning Integration Points

```python
# Add learning context to every major action
if self.learning_mode:
    self.learning_system.explain_concept(
        concept="port_scanning",
        context=f"Scanning {target} to discover services"
    )
```

### 4. Configuration Management

```python
# config.py
DEFAULT_CONFIG = {
    'scan_timeout': 300,
    'max_threads': 10,
    'learning_mode': True,
    'verbose_output': False,
    'tool_paths': {
        'nmap': '/usr/bin/nmap',
        'nikto': '/usr/bin/nikto'
    }
}
```

## Deployment Guide

### Local Installation

```bash
# Development mode
pip install -e .

# Production installation
pip install secops-cli-wrapper
```

### Distribution

```bash
# Build package
python setup.py sdist bdist_wheel

# Upload to PyPI (when ready)
twine upload dist/*
```

### Docker Deployment

```dockerfile
FROM python:3.9-slim

# Install security tools
RUN apt-get update && apt-get install -y nmap nikto clamav

# Install Python package
COPY . /app
WORKDIR /app
RUN pip install -e .

ENTRYPOINT ["secops"]
```

## Success Metrics

### Week 2 Goals:
- [ ] CLI responds to basic commands
- [ ] Nmap integration functional
- [ ] GitHub repository with CI/CD
- [ ] Basic learning explanations

### Week 4 Goals:
- [ ] Intelligent tool selection working
- [ ] 3+ security tools integrated
- [ ] Result correlation functional
- [ ] Comprehensive test coverage

### Week 6 Goals:
- [ ] Full learning mode implemented
- [ ] Professional user experience
- [ ] Complete documentation
- [ ] Ready for deployment

## Troubleshooting Common Issues

### VSCode Issues:
```bash
# Python interpreter not found
Ctrl+Shift+P -> "Python: Select Interpreter" -> Choose ./venv/bin/python

# Import errors
# Ensure PYTHONPATH includes project root
export PYTHONPATH="${PYTHONPATH}:/path/to/secops-cli-wrapper"
```

### Tool Integration Issues:
```bash
# Tool not found
which nmap  # Check if installed
sudo apt install nmap  # Install if missing

# Permission issues
sudo chmod +x ./main.py
```

### GitHub Issues:
```bash
# Authentication problems  
gh auth login
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

This comprehensive guide provides everything needed to build the intelligent SecOps CLI wrapper from start to finish, with specific attention to the tools and environment you're familiar with.
