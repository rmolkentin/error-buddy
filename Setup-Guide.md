# Error Buddy + Ollama Setup Guide

This guide helps Canonical employees install a local Ollama model and connect it to the `error-buddy` snap.

## Prerequisites

- Ubuntu workstation with terminal access
- `sudo` access
- Internet access to download Ollama and model weights

## 1) Install Ollama

Install Ollama using the official installer:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Confirm the install:

```bash
ollama --version
```

## 2) Select and run a local model

See the Ollama model library if you want alternatives:

- [Ollama Library](https://ollama.com/library)

Recommended model for `error-buddy`:

```bash
ollama run qwen2.5-coder:32b
```

You can use any local model, but if you choose a different one, set it during `error-buddy init`.

## 3) Install the Error Buddy snap

If not already installed:

```bash
sudo snap install error-buddy
```

If you are testing a local snap artifact:

```bash
sudo snap install --dangerous ./error-buddy_1.9_amd64.snap
```

## 4) Connect required snap interfaces

`error-buddy` needs access to:
- network (auto-connected by snapd)
- personal config file (`~/.error-buddy`)

Run:

```bash
sudo snap connect error-buddy:dot-error-buddy
```

## 5) Initialize Error Buddy for Ollama

Run:

```bash
error-buddy init
```

When prompted, use:
- Ollama API URL: `http://localhost:11434/api/generate`
- Ollama model: `llama3.1:8b` (or your preferred local model)

This writes the config to:

```text
~/.error-buddy
```

## 6) Quick validation

Test AI analysis with a known product nickname:

```bash
error-buddy maas "failed to power on"
```

You should see:
- an AI analysis section (from local Ollama)
- source code search URL
- Launchpad bug search URL

## Troubleshooting

### Ollama connection error

- Confirm Ollama is running:
  ```bash
  ollama list
  ```
- Confirm endpoint is reachable:
  ```bash
  curl http://localhost:11434/api/tags
  ```
- Re-run `error-buddy init` and verify URL/model values.

### Snap permission denied for config file

Reconnect:

```bash
sudo snap connect error-buddy:dot-error-buddy
```

### Model not found

Pull it locally:

```bash
ollama pull <model-name>
```

Then re-run:

```bash
error-buddy init
```
