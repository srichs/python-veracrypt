"""Python wrapper around the VeraCrypt CLI."""

from enum import Enum
from typing import List, Optional, Tuple
import logging
import os
import platform
import subprocess


class Encryption(Enum):
    """Supported VeraCrypt encryption algorithms."""
    AES = "AES"
    SERPENT = "Serpent"
    TWOFISH = "Twofish"
    CAMELLIA = "Camellia"
    KUZNYECHIK = "Kuznyechik"
    AES_TWOFISH = "AES(Twofish)"
    TWOFISH_SERPENT = "Twofish(Serpent)"
    SERPENT_AES = "Serpent(AES)"
    SERPENT_TWOFISH_AES = "Serpent(Twofish(AES))"
    AES_SERPENT = "AES(Serpent)"
    KUZNYECHIK_CAMELLIA = "Kuznyechik(Camellia)"
    CAMELLIA_KUZNYECHIK = "Camellia(Kuznyechik)"


class Hash(Enum):
    """Supported VeraCrypt hash algorithms."""
    SHA256 = "sha-256"
    SHA512 = "sha-512"
    WHIRLPOOL = "whirlpool"
    BLAKE2S = "blake2s"
    RIPEMD160 = "ripemd-160"
    STREEBOG = "streebog"


class FileSystem(Enum):
    """Supported filesystem formats for newly created volumes."""
    NONE = "None"
    FAT = "FAT"
    EXFAT = "exFAT"
    NTFS = "NTFS"
    EXT2 = "ext2"
    EXT3 = "ext3"
    EXT4 = "ext4"
    HFS = "HFS"
    APFS = "APFS"


class VeraCryptError(RuntimeError):
    """Raised when VeraCrypt operations fail."""


class VeraCrypt(object):
    """Cross-platform wrapper for core VeraCrypt CLI operations.

    The class wraps the VeraCrypt CLI to create, mount, and dismount volumes on Windows,
    macOS, and Linux systems. Windows uses ``/param value`` arguments and separates the
    mount/dismount tool (``VeraCrypt.exe``) from the format tool (``VeraCrypt Format.exe``),
    while Linux/macOS use ``--param value`` arguments against a single executable.

    Extra CLI options can be supplied to the public methods, but invalid options will
    result in a VeraCrypt CLI error.

    The :meth:`command` method allows arbitrary command execution. On Windows, set
    ``windows_program="VeraCrypt Format.exe"`` to target the volume creation CLI.

    **WARNING:** On Windows the VeraCrypt CLI does not accept passwords from stdin. The
    password will be present in the subprocess arguments for the duration of the call.
    The returned ``CompletedProcess.args`` has the password masked for logging safety.

    :param log_level: Logging level to use. Defaults to ``logging.ERROR``.
    :param log_fmt: Logging format string.
    :param log_datefmt: Date format string used in log messages.
    :param veracrypt_path: Path to the VeraCrypt executable. On Windows, this should be
        the directory containing the executables. On macOS/Linux, this should be the
        full path to the VeraCrypt binary. If ``None``, a platform-specific default is
        discovered.
    """
    def __init__(
        self, 
        log_level: Optional[int] = logging.ERROR, 
        log_fmt: Optional[str] = "%(levelname)s:%(module)s:%(funcName)s:%(message)s", 
        log_datefmt: Optional[str] = "%Y-%m-%d %H:%M:%S",
        veracrypt_path: Optional[str] = None
    ):
        logging.basicConfig(level=log_level, format=log_fmt, datefmt=log_datefmt)
        self.logger = logging.getLogger('veracrypt.py')
        self.os_name = platform.system()
        self.veracrypt_path = veracrypt_path or self._default_path()
        self.logger.info('Object initialized')

    def _default_path(self) -> str:
        """Return the default VeraCrypt CLI path for the current platform."""
        self.logger.debug('Getting default path')

        if self.os_name == 'Windows':
            path = os.path.join('C:\\', 'Program Files', 'VeraCrypt')
            path1 = os.path.join(path, 'VeraCrypt.exe')
            path2 = os.path.join(path, 'VeraCrypt Format.exe')

            if not os.path.exists(path1):
                raise VeraCryptError(f'VeraCrypt.exe not found at {path1}')
            if not os.path.exists(path2):
                raise VeraCryptError(f'"VeraCrypt Format.exe" not found at {path2}')
        elif self.os_name == 'Darwin':  # macOS
            path = os.path.join('/', 'Applications', 'VeraCrypt.app', 'Contents', 'MacOS', 'VeraCrypt')
        elif self.os_name == 'Linux':
            path = os.path.join('/', 'usr', 'bin', 'veracrypt')
        else:
            raise VeraCryptError("Unsupported Operating System")
        
        self._check_path(path)
        self.logger.info(f'VeraCrypt program path found at {path}')
        return path

    def _check_path(self, path: str) -> bool:
        """Validate that a path exists.

        :param path: Filesystem path to validate.
        :raises VeraCryptError: If the path does not exist.
        :return: ``True`` when the path exists.
        """
        if os.path.exists(path):
            self.logger.debug(f'Path {path} exists')
            return True
        else:
            raise VeraCryptError(f'The path {path} does not exist')

    def mount_volume(
        self, 
        volume_path: str, 
        password: str,
        mount_point: Optional[str] = None,
        options: Optional[List[str]] = None
    ) -> subprocess.CompletedProcess:
        """Mount a VeraCrypt volume.

        :param volume_path: Path to the volume file to mount.
        :param password: Password for the volume.
        :param mount_point: Target mount point (drive letter on Windows).
        :param options: Additional CLI options. Options differ by platform.
        :raises VeraCryptError: If the CLI call fails.
        :return: ``subprocess.CompletedProcess`` for the CLI invocation.
        """
        self.logger.debug('Mounting volume')
        self._check_path(volume_path)

        if self.os_name == 'Windows':
            cmd = self._mount_win(volume_path, password, mount_point, options)
        else:
            cmd = self._mount_nix(volume_path, mount_point, options)
            self.logger.debug(f'Command created: {cmd}')

        try:
            if self.os_name == 'Windows':
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                pword = '*' * len(password)
                result.args[4] = pword
            else:
                result = subprocess.run(cmd, input=password + '\n', capture_output=True, text=True, check=True)
            self.logger.info(f'Command executed: returned {result.returncode}')
            self.logger.debug(f'{result.stdout}')
            return result
        except subprocess.CalledProcessError as e:
            raise VeraCryptError(f'Error mounting volume: {e.stderr}')
    
    def _mount_win(
        self, 
        volume_path: str, 
        password: str,
        mount_point: Optional[str] = None,
        options: Optional[List[str]] = None
    ) -> List[str]:
        """Build the Windows CLI command for mounting a volume."""
        self.logger.debug('Mounting volume on Windows')
        cmd = [
            os.path.join(self.veracrypt_path, 'VeraCrypt.exe'),
            '/volume', volume_path,
            '/password', password
        ]

        if mount_point:
            cmd += ['/letter', mount_point]

        if options:
            cmd += options
        cmd += ['/quit', '/silent', '/force']
        self.logger.debug('Mount command generated')
        return cmd

    def _mount_nix(
        self,
        volume_path: str,
        mount_point: Optional[str] = None,
        options: Optional[List[str]] = None
    ) -> List[str]:
        """Build the Linux/macOS CLI command for mounting a volume."""
        self.logger.debug('Mounting volume on Linux/MacOS')
        cmd = [
            'sudo',
            self.veracrypt_path,
            '--text',
            '--non-interactive',
            '--mount', volume_path
        ]

        if mount_point:
            cmd += [mount_point]

        if options:
            cmd += options
        cmd += ['--stdin', '--force']
        self.logger.debug('Mount command generated')
        return cmd

    def dismount_volume(self, target: str = 'all', options: Optional[List[str]] = None) -> subprocess.CompletedProcess:
        """Dismount a VeraCrypt volume or all mounted volumes.

        :param target: Mount point to dismount. Use ``"all"`` to dismount all volumes.
        :param options: Additional CLI options.
        :raises VeraCryptError: If the CLI call fails.
        :return: ``subprocess.CompletedProcess`` for the CLI invocation.
        """
        self.logger.debug('Dismounting volume')

        if self.os_name == 'Windows':
            cmd = self._dismount_win(target, options)
        else:
            cmd = self._dismount_nix(target, options)
            self.logger.debug(f'Command created: {cmd}')

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            self.logger.info(f'Command executed: returned {result.returncode}')
            self.logger.debug(f'{result.stdout}')
            return result
        except subprocess.CalledProcessError as e:
            raise VeraCryptError(f'Error dismounting volume: {e.stderr}')

    def _dismount_win(self, target: str = 'all', options: Optional[List[str]] = None) -> List[str]:
        """Build the Windows CLI command for dismounting volumes."""
        self.logger.debug('Dismounting volume on Windows')
        cmd = [os.path.join(self.veracrypt_path, 'VeraCrypt.exe'), '/dismount']

        if target != 'all':
            cmd.append(target)
        
        if options:
            cmd += options
        cmd += ['/quit', '/silent', '/force']
        self.logger.debug('Dismount command generated')
        return cmd
    
    def _dismount_nix(self, target: str = 'all', options: Optional[List[str]] = None) -> List[str]:
        """Build the Linux/macOS CLI command for dismounting volumes."""
        self.logger.debug('Dismounting volume on Linux/MacOS')
        cmd = ['sudo', self.veracrypt_path, '--text', '--non-interactive', '--unmount']

        if target != 'all':
            self._check_path(target)
            cmd.append(target)
        
        if options:
            cmd += options
        self.logger.debug('Dismount command generated')
        return cmd
    
    def create_volume(
        self,
        volume_path: str,
        password: str,
        size: int,
        encryption: Encryption = Encryption.AES,
        hash_alg: Hash = Hash.SHA512,
        filesystem: FileSystem = FileSystem.FAT,
        keyfiles: Optional[List[str]] = None,
        hidden: bool = False,
        options: Optional[List[str]] = None
    ) -> subprocess.CompletedProcess:
        """Create a new VeraCrypt volume.

        :param volume_path: Destination path for the volume file.
        :param password: Password for the volume.
        :param size: Volume size in bytes.
        :param encryption: Encryption algorithm to use.
        :param hash_alg: Hash algorithm to use.
        :param filesystem: Filesystem format to apply.
        :param keyfiles: Optional keyfiles to include in encryption.
        :param hidden: Whether to create a hidden volume.
        :param options: Additional CLI options.
        :raises VeraCryptError: If the CLI call fails.
        :return: ``subprocess.CompletedProcess`` for the CLI invocation.
        """
        self.logger.debug('Creating volume')

        if self.os_name == 'Windows':
            cmd = self._create_win(volume_path, password, size, encryption, hash_alg, filesystem, keyfiles)
        else:
            if self.os_name == 'Darwin':
                if not os.path.exists(volume_path):
                    with open(volume_path, 'w'):
                        pass
            cmd = self._create_nix(volume_path, size, encryption, hash_alg, filesystem, keyfiles, hidden)
            self.logger.debug(f'Command created: {cmd}')

        try:
            result = None
            if self.os_name == 'Windows':
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                pword = '*' * len(password)
                result.args[4] = pword
            else:
                result = subprocess.run(cmd, input=password + '\n', capture_output=True, text=True, check=True)
            self.logger.info(f'Command executed: returned {result.returncode}')
            self.logger.debug(f'{result.stdout}')
            return result
        except subprocess.CalledProcessError as e:
            raise VeraCryptError(f'Error creating volume: {e.stderr}')
    
    def _create_win(
        self,
        volume_path: str,
        password: str,
        size: int,
        encryption: Encryption = Encryption.AES,
        hash_alg: Hash = Hash.SHA512,
        filesystem: FileSystem = FileSystem.FAT,
        keyfiles: Optional[List[str]] = None,
        options: Optional[List[str]] = None
    ) -> List[str]:
        """Build the Windows CLI command for creating a volume."""
        self.logger.debug('Creating volume on Windows')
        cmd = [
            os.path.join(self.veracrypt_path, 'VeraCrypt Format.exe'),
            '/create', volume_path,
            '/password', password,
            '/size', f'{size}',
            '/encryption', encryption.value,
            '/hash', hash_alg.value,
            '/filesystem', filesystem.value,
        ]

        if keyfiles:
            for keyfile in keyfiles:
                cmd += ['/keyfile', keyfile]

        if options:
            cmd += options
        cmd += ['/protectMemory', '/quick', '/silent', '/force']
        self.logger.debug('Create command generated')
        return cmd
    
    def _create_nix(
        self,
        volume_path: str,
        size: int,
        encryption: Encryption = Encryption.AES,
        hash_alg: Hash = Hash.SHA512,
        filesystem: FileSystem = FileSystem.FAT,
        keyfiles: Optional[List[str]] = None,
        hidden: bool = False,
        options: Optional[List[str]] = None
    ) -> List[str]:
        """Build the Linux/macOS CLI command for creating a volume."""
        self.logger.debug('Creating volume on Linux/MacOS')
        cmd = [
            'sudo',
            self.veracrypt_path,
            '--text',
            '--non-interactive',
            '--create', volume_path,
            '--size', f'{size}',
            '--encryption', encryption.value,
            '--hash', hash_alg.value,
            '--filesystem', filesystem.value
        ]

        if keyfiles:
            for keyfile in keyfiles:
                cmd += ['--keyfiles', keyfile]

        if hidden:
            cmd += ['--volume-type', 'hidden']
        
        if options:
            cmd += options
        cmd += ['--random-source', '/dev/urandom', '--stdin', '--quick', '--force']
        self.logger.debug('Create command generated')
        return cmd
    
    def command(
        self,
        options: Optional[List[str]] = None,
        windows_program: Optional[str] = "VeraCrypt.exe"
    ) -> subprocess.CompletedProcess:
        """Call the VeraCrypt CLI with custom options.

        :param options: Options to pass to the VeraCrypt CLI.
        :param windows_program: Windows-only program name to invoke.
        :raises VeraCryptError: If the CLI call fails.
        :return: ``subprocess.CompletedProcess`` for the CLI invocation.
        """
        self.logger.debug('Calling custom command')
        if self.os_name == 'Windows':
            cmd = self._custom_win(options, windows_program)
            password, index = self._get_password(cmd)
        else:
            password, index = self._get_password(options)
            cmd = self._custom_nix(options)
            self.logger.debug(f'Command created: {cmd}')

        try:
            result = None
            if self.os_name == 'Windows':
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                if password is not None:
                    self.logger.debug('Sanitizing password')
                    pword = '*' * len(password)
                    result.args[index] = pword
            else:
                if password is not None:
                    result = subprocess.run(cmd, input=password + '\n', capture_output=True, text=True, check=True)
                else:
                    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            self.logger.info(f'Command executed: returned {result.returncode}')
            self.logger.debug(f'{result.stdout}')
            return result
        except subprocess.CalledProcessError as e:
            raise VeraCryptError(f'Error calling custom command: {e.stderr}')

    def _custom_win(self, options: Optional[List[str]] = None, windows_program: Optional[str] = "VeraCrypt.exe") -> List[str]:
        """Build a Windows CLI command using an arbitrary VeraCrypt executable."""
        self.logger.debug('Calling custom command on Windows')
        cmd = [os.path.join(self.veracrypt_path, windows_program)]
        
        if options:
            cmd += options
        self.logger.debug('Custom command generated')
        return cmd
    
    def _custom_nix(self, options: Optional[List[str]] = None) -> List[str]:
        """Build a Linux/macOS CLI command using provided options."""
        self.logger.debug('Calling custom command on Linux/MacOS')
        password, p_index = self._get_password(options)
        cmd = ['sudo', self.veracrypt_path]

        if password and options:
            self.logger.debug('Removing password from command line options')
            del options[p_index - 1:p_index + 1]
        
        if options:
            cmd += options
        
        if password:
            if '--stdin' not in options:
                cmd += ['--stdin']
        self.logger.debug('Custom command generated')
        return cmd
    
    def _get_password(self, cmd: Optional[List[str]]) -> Tuple[Optional[str], int]:
        """Extract a password argument from a command list.

        :param cmd: Command list or ``None``.
        :return: Tuple of password value and index where it was found.
        """
        if not cmd:
            return None, -1
        pword_option = '--password'
        if self.os_name == 'Windows':
            pword_option = '/password'
        
        try:
            index = cmd.index(pword_option) + 1
            pword = cmd[index]
        except ValueError:
            pword = None
            index = -1
        return pword, index
