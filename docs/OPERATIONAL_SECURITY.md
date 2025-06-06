# 🔐 Operational Security Guide

## Secure Configuration
```yaml
# ~/.bugmapx/config.yaml
tor:
  enabled: true
  password: "$(openssl rand -hex 16)"   # Always auto-generate
  ports: [9050, 9150]                   # Custom ports

ai:
  model: medium
  openai_key: "vault::encrypted_value"  # Use encrypted secrets
