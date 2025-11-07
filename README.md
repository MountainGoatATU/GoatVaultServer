# GoatVaultServer

Development API server for GoatVault password manager.

## Requirements

- Python >=3.12
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

## Installation

### Clone Repository

```bash
git clone https://github.com/MountainGoatATU/GoatVaultServer.git
cd GoatVaultServer
```

### Install dependencies

#### Using uv (recommended)

```bash
uv sync
```

#### Using pip

```bash
pip install -e .
```

## Usage

```bash
uv run uvicorn app.main:app --reload
```
- Visit http://localhost:8000/docs for API documentation
