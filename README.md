[![codecov](https://codecov.io/gh/MountainGoatATU/GoatVaultServer/graph/badge.svg?token=B5HBATGFL2)](https://codecov.io/gh/MountainGoatATU/GoatVaultServer)
[![CodeScene Average Code Health](https://codescene.io/projects/76220/status-badges/average-code-health?component-name=Goatvaultserver)](https://codescene.io/projects/76220/architecture/biomarkers?component=Goatvaultserver)
[![CodeScene System Mastery](https://codescene.io/projects/76220/status-badges/system-mastery?component-name=Goatvaultserver)](https://codescene.io/projects/76220/)

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

### Production Server

```bash
uv run task server
```

### Development Server

```bash
uv run task dev
```

### Run tests with coverage

```bash
uv run task test
```

- Visit http://localhost:8000/docs for API documentation
