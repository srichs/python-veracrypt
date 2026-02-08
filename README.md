# python-veracrypt

[![CI](https://github.com/srichs/python-veracrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/srichs/python-veracrypt/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/python-veracrypt.svg)](https://pypi.org/project/python-veracrypt/)

## Overview

A cross platform Python wrapper for the [VeraCrypt](https://veracrypt.eu) CLI. It requires the VeraCrypt application to be installed on your system and it uses the CLI to perform different operations.

## Installation

Install the Python package with pip:

```bash
pip install python-veracrypt
```

You must also install VeraCrypt and ensure the VeraCrypt CLI is available on your PATH. Refer to the VeraCrypt downloads page for installers and platform details:

- [VeraCrypt Downloads](https://veracrypt.eu/en/Downloads.html)

### Prerequisites

- Verify the VeraCrypt CLI is available by running `veracrypt --version` (or the equivalent command on your OS).
- Ensure the process has permission to mount volumes (administrator or sudo may be required).

## Supported Platforms

- Windows
- macOS
- Linux

Mount operations may require administrator or sudo permissions depending on your OS and system configuration.

## Usage

```python
from veracrypt import VeraCrypt, FileSystem
import os


vc = VeraCrypt()
volume_path = os.path.join('C:\\', 'Users', 'user', 'Desktop', 'test.vc')
# Create a volume
result = vc.create_volume(volume_path, 'SecretPassword', 5 * 1024 * 1024, filesystem=FileSystem.EXFAT)

# Mount a volume
result = vc.mount_volume(volume_path, 'SecretPassword', 'H', options=['/beep'])
# Dismount a volume
result = vc.dismount_volume('H', options=['/beep'])

# Custom command - Pay close attention when using this
result = vc.command(['/volume', volume_path, '/letter', 'H', '/password', 'SecretPassword', '/beep', '/quit', '/silent', '/force'])
```

### Quick start checklist

1. Install VeraCrypt and confirm the CLI is on your PATH.
2. Choose a volume path and mount target (drive letter on Windows or mount point on Unix).
3. Use the helper methods to create, mount, and dismount volumes.

### Linux/macOS example

```python
from veracrypt import VeraCrypt, FileSystem

vc = VeraCrypt()
volume_path = "/home/user/secure/test.vc"
mount_point = "/mnt/veracrypt"

result = vc.create_volume(volume_path, "SecretPassword", 5 * 1024 * 1024, filesystem=FileSystem.EXFAT)
result = vc.mount_volume(volume_path, "SecretPassword", mount_point, options=["--filesystem=exfat"])
result = vc.dismount_volume(mount_point)
```

### Handling results

The methods on `VeraCrypt` return `subprocess.CompletedProcess` objects. You can inspect the return code and stderr to verify success:

```python
result = vc.mount_volume(volume_path, "SecretPassword", "H", options=["/beep"])
if result.returncode != 0:
    print("Mount failed:", result.stderr)
```

## Security

### Passwords

On nix based systems the password is passed in using `--stdin`, so the password will not appear in bash history or log files. 

On Windows based systems the password cannot be passed to the CLI using stdin, so care should be taken to ensure that the password will not appear in history or logs. The result that is returned from the basic functional commands of the VeraCrypt class are `subprocess.CompletedProcess` objects, and the password is sanitized on windows in the `args` parameter of the object.

### Best practices

- Avoid hardcoding passwords in source code. Prefer secure prompts or environment variables.
- Avoid logging the full command line if it contains sensitive values.
- Ensure mounted volumes are dismounted when not in use.

## Documentation

Sphinx documentation lives in the `docs/sphinx/` directory. To build HTML docs locally:

```bash
pip install ".[docs]"
sphinx-build -b html docs/sphinx docs/sphinx/_build/html
```

The generated docs can be opened from `docs/sphinx/_build/html/index.html`.

### Troubleshooting

- If mounts fail, verify the VeraCrypt CLI works outside Python and that your user has sufficient permissions.
- If you use a custom VeraCrypt install location, ensure the executable directory is on your PATH.

## Contributing

- Install development dependencies with `pip install -r requirements-dev.txt`.
- Run tests with `pytest`.
- Format with `black` and sort imports with `isort`.
- Lint with `ruff` and type-check with `mypy`.

## License

This project is licensed under the terms of the LICENSE file in this repository.

## References

1. [VeraCrypt](https://veracrypt.eu)

1. [Arcane Code VeraCrypt on Command Line Windows](https://arcanecode.com/2021/06/14/veracrypt-on-the-command-line-for-windows/)

1. [Arcane Code VeraCrypt on Command Line Linux](https://arcanecode.com/2021/06/21/veracrypt-on-the-command-line-for-ubuntu-linux/)

1. [Arcane Code VeraCrypt on Command Line MacOS](https://arcanecode.com/2021/06/07/3504/)

1. [GitHub - arcanecode/VeraCrypt-CommandLine-Examples](https://github.com/arcanecode/VeraCrypt-CommandLine-Examples)
