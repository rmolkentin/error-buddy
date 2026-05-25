# error-buddy

Error Buddy is an error auditor and code locator for Canonical products. It combines local log analysis, AI-powered insights using Ollama, and deep product source code searching to help diagnose system issues quickly.

Best used with sos report directories, log files, or product error messages.

## Quick Start

```bash
# Configure Ollama integration (one-time setup)
error-buddy init

# Validate your setup
error-buddy doctor

# Analyze a local log or sosreport
error-buddy ./syslog
error-buddy ~/sosreport-archive.tar.gz

# Search a product's source for error messages
error-buddy maas "failed to power on"
error-buddy juju "relation error"

# Interactive sosreport investigation
error-buddy sosreport

# List all supported products
error-buddy --list-products
```

## Usage Modes

### 1. Local Log Audit
Scan log files or directories for FATAL, CRITICAL, ERROR, and WARNING level messages. Error Buddy automatically groups multi-line tracebacks into clean, readable tables.

**Example:**
```bash
error-buddy /var/log/syslog
error-buddy ~/sos/sosreport-example/var/log/maas
error-buddy ./var/log/  # scan entire directory
```

**What it does:**
- Extracts error/warning patterns from text files
- Groups traceback lines for readability
- Displays results in a formatted table
- Supports `.log`, `.txt`, `.out`, `.err` files and system logs like syslog, dmesg, kern.log, auth.log

### 2. Product Error Search
Search a product's GitHub repository for relevant error messages and retrieve source code context, bug reports, and AI analysis.

**Example:**
```bash
error-buddy landscape-server "No user with access key"
error-buddy cloud-init "Failed to parse"
error-buddy lxd "permission denied"
```

**What it does:**
- Generates a GitHub code search URL for the product repository
- Creates a Launchpad bug search URL with matching terms
- Optionally runs local Ollama AI analysis for deeper insights

### 3. Sosreport Interactive Analysis
Two-step AI-powered sosreport investigation using local Ollama. The first pass triages the sosreport to identify key files and keywords. The second pass performs targeted analysis with evidence snippets.

**Example:**
```bash
error-buddy sosreport
# Then interactively provide:
# - Path to sosreport file/directory
# - Description of the issue to investigate
```

**What it does:**
- Scans entire sosreport for error patterns
- Uses AI triage to identify relevant files and keywords
- Collects targeted evidence snippets
- Generates structured analysis with root causes, logs, and next steps

### 4. Generic Error Analysis
Pass a single error message for AI analysis without specifying a product. Returns Launchpad bug search results and local Ollama insights.

**Example:**
```bash
error-buddy "camera failed to initialize"
error-buddy "systemd service timed out"
```

### 5. Initialization and Diagnostics

**Configure Ollama:**
```bash
error-buddy init
```
Sets up the local Ollama endpoint and model preference in `~/.error-buddy`.

**Validate setup:**
```bash
error-buddy doctor
```
Tests Ollama connectivity, configuration, and model availability.

## Installation

### From snap (stable)
```bash
sudo snap install error-buddy
sudo snap connect error-buddy:dot-error-buddy  # grant config file access
```

### From local snap (development)
```bash
sudo snap install --dangerous ./error-buddy_*.snap
sudo snap connect error-buddy:dot-error-buddy
```

## Setup

See [Setup-Guide.md](Setup-Guide.md) for complete Ollama and error-buddy configuration steps.

**Quick setup summary:**
1. Install Ollama: `curl -fsSL https://ollama.com/install.sh | sh`
2. Run a local model: `ollama run qwen2.5-coder:7b`
3. Install error-buddy snap
4. Connect interfaces: `sudo snap connect error-buddy:dot-error-buddy`
5. Initialize: `error-buddy init` (set Ollama URL and model)
6. Test: `error-buddy doctor`

## Supported Products

Error Buddy recognizes these product nicknames for deep error search:

- `landscape-client`, `landscape-server`
- `maas`, `lxd`, `juju`
- `cloud-init`, `curtin`
- `subiquity`, `autoinstall`
- `microk8s`, `microstack`
- `charmed-kubernetes`
- `ubuntu-desktop-installer`
- `snapd`, `snapcraft`, `charmcraft`, `rockcraft`
- `cos-lite`
- `netplan`
- `openstack`, `charm` (OpenStack charmers)

View the full list with: `error-buddy --list-products`

## Environment Variables

### Ollama Configuration
- `ERROR_BUDDY_OLLAMA_TIMEOUT`: Request timeout in seconds (default: 120)
- `ERROR_BUDDY_OLLAMA_NUM_PREDICT`: Max output tokens (default: 1000)
- `ERROR_BUDDY_MULTI_PASS`: Enable refinement passes (default: false; set to 1, true, yes, or on)
- `ERROR_BUDDY_DEBUG_PROMPTS`: Print prompts sent to Ollama (default: false)

### Examples
```bash
# Increase timeout for slow models
ERROR_BUDDY_OLLAMA_TIMEOUT=180 error-buddy maas "error message"

# Enable multi-pass analysis for better results
ERROR_BUDDY_MULTI_PASS=1 error-buddy sosreport

# Debug AI prompts
ERROR_BUDDY_DEBUG_PROMPTS=1 error-buddy juju "trace"
```

## Features

### AI-Powered Analysis
When Ollama is configured, Error Buddy provides:
- Accurate root-cause assessment based on evidence
- Identification of affected components
- Actionable next steps and verification checks
- Links to relevant official documentation
- Multi-pass refinement for complex issues (optional)

### Smart Triage
- Automatically prioritizes system logs, journal files, and failed unit captures
- Identifies affected product from filenames and error keywords
- Reduces large sosreports to focused evidence sets

### Integration with Canonical Tools
- Searches Canonical GitHub repositories for source code
- Finds related Launchpad bug reports
- Links to official Ubuntu and product documentation
- Compatible with sosreport format (tar, tar.gz, tar.xz, zip)

## Configuration

Error Buddy stores configuration in `~/.error-buddy`:

```json
{
  "ollama_url": "http://localhost:11434/api/generate",
  "ollama_model": "qwen2.5-coder:7b"
}
```

Reconfigure at any time with: `error-buddy init`

## Troubleshooting

### Ollama not reachable
- Verify Ollama is running: `ollama list`
- Test endpoint: `curl http://localhost:11434/api/tags`
- Check URL in config: `cat ~/.error-buddy`
- Reconnect snap interface: `sudo snap connect error-buddy:dot-error-buddy`

### Model not found
- List available models: `ollama list`
- Pull a model: `ollama pull qwen2.5-coder:7b`
- Reconfigure: `error-buddy init`

### Permission denied on config file
- Reconnect storage plug: `sudo snap connect error-buddy:dot-error-buddy`

### Slow analysis
- Use `ERROR_BUDDY_OLLAMA_TIMEOUT=300` for longer timeouts
- Try a smaller model (e.g., `mistral:7b` instead of `qwen2.5-coder:32b`)
- Check system resources: `free -h`

## Examples

### Audit a system log for errors
```bash
error-buddy /var/log/syslog
```

### Investigate a MAAS power-on failure
```bash
error-buddy maas "failed to power on"
```

### Diagnose a Juju deployment issue from sosreport
```bash
error-buddy sosreport
# Provide: path to sosreport, description of issue
```

### Search for generic error without product context
```bash
error-buddy "permission denied" --no-ai
```

### Run product search without AI (faster)
```bash
error-buddy cloud-init "timeout" --no-ai
```

## Architecture

Error Buddy consists of:

- **Log Parser**: Extracts and deduplicates error messages from local logs
- **Triage Engine**: AI-driven identification of relevant sosreport files
- **Context Collector**: Intelligently samples and prioritizes log snippets
- **AI Orchestrator**: Multi-pass analysis with Ollama (optional)
- **Search URL Generator**: Creates GitHub and Launchpad URLs for follow-up

Data flows locally; no telemetry or external AI services are used.

## License

Apache 2.0

## Feedback & Contributions

For issues, feature requests, or contributions, please visit the [GitHub repository](https://github.com/rmolkentin/error-buddy).
