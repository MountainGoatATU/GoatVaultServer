# GoatVaultServer

Development API server for GoatVault password manager.

## Requirements

- Python >=3.12
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

## Installation

### Using uv (recommended)

```bash
git clone https://github.com/x0rtex/DobryDo.git
cd dobrydo
uv sync
```

### Using pip

```bash
git clone https://github.com/x0rtex/DobryDo.git
cd dobrydo
pip install -e .
```

## Usage

```bash
uv run uvicorn app.main:app --reload
```
