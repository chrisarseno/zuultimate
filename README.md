# Zuultimate

Enterprise identity, vault, zero-trust, and AI security platform.

## Quick Start

```bash
# Install (editable, with dev deps)
pip install -e ".[dev]"

# Run tests
pytest tests/ -q

# Start dev server
uvicorn zuultimate.app:create_app --factory --reload --port 8000

# CLI
zuul serve          # Start server
zuul scan "text"    # Scan text for threats
zuul redteam        # Run red team suite
zuul health         # Check health
```

## Modules

| Module | Status |
|--------|--------|
| AI Security | Implemented |
| Vault (crypto) | Implemented |
| Plugins | Implemented |
| Identity | Stub |
| Access | Stub |
| Vault (service) | Stub |
| POS | Stub |
| CRM | Stub |
| Backup/Resilience | Stub |

## Configuration

Copy `.env.example` to `.env` and adjust values. All settings use the `ZUUL_` prefix.

## Docker

```bash
docker compose up --build
```
