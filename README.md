# Ops Audit Toolkit

A lightweight security and configuration audit toolkit designed for CI/CD pipelines and infrastructure deployments.

## Features
- Automated YAML/JSON infrastructure config validation.
- Detects security misconfigurations and exposed credential patterns.
- Designed for seamless integration into GitHub Actions.

## Getting Started
```bash
pip install -r requirements.txt
python auditor.py --path ./configs
