[![codecov](https://codecov.io/gh/MountainGoatATU/GoatVaultServer/branch/main/graph/badge.svg)](https://codecov.io/gh/MountainGoatATU/GoatVaultServer)

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
