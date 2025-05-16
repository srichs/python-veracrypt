# python-veracrypt

## Overview

A cross platform Python wrapper for the VeraCrypt CLI. It requires the VeraCrypt application to be installed on your system and it uses the CLI to perform different operations.

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
```

## Security

### Passwords

On nix based systems the password is passed in using `--stdin`, so the password will not appear in bash history or log files. 

On Windows based systems the password cannot be passed to the CLI using stdin, so care should be taken to ensure that the password will not appear in history or logs. The result that is returned from the basic functional commands of the VeraCrypt class are `subprocess.CompletedProcess` objects, and the password is sanitized on windows in the `args` parameter of the object.
