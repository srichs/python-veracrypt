from enum import Enum
from typing import List, Optional, Tuple
import logging
import os
import platform
import subprocess


class Encryption(Enum):
    """
    An Enum for the VeraCrypt Encryption type.
    """
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
    """
    An Enum for the VeraCrypt Hash type.
    """
    SHA256 = "sha-256"
    SHA512 = "sha-512"
    WHIRLPOOL = "whirlpool"
    BLAKE2S = "blake2s"
    RIPEMD160 = "ripemd-160"
    STREEBOG = "streebog"


class FileSystem(Enum):
    """
    An Enum for the File System formatting.
    """
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
    pass


class VeraCrypt(object):
    """
    The VeraCrypt class is a cross platform tool wrapper used to do basic tasks using the 
    VeraCrypt CLI. This class allows a user to create, mount, and dismount a volume
    on Windows, MacOS, or Linux as long as VeraCrypt has been installed. 
    
    There are major differences between the VeraCrypt CLI on Windows versus on Linux/MacOS. Parameters 
    are passed on the Windows CLI in the format '/param value', while on Linux/MacOS the parameters
    are passed in the format '--param value'. On Windows there are two CLI programs, VeraCrypt.exe
    which performs the mounting and dismounting of volumes, and 'VeraCrypt Format.exe' which
    performs the creation of volumes. The Windows CLI options are slightly different than the
    Linux/MacOS options, and care should be taken to ensure that the correct options are used so
    there are no errors.

    Care should be taken when passing additional options to each of the public methods, if the
    option is not valid for the CLI then an error will occur.

    The command() method allows the user to supply a custom command to the VeraCrypt CLI. The method
    takes a list of options that will be called with the VeraCrypt command. On Windows you should
    pass the parameter windows_program='VeraCrypt Format.exe' if you would like to create a volume
    using a custom command. The default windows_program value is for the 'VeraCrypt.exe' program.

    :param log_level: the logging level to be used for debugging, default: logging.ERROR
    :param log_fmt: the format to be used for logging messages
    :param log_datefmt: the date format to use in logging messages if included in format
    :param veracrypt_path: the path to the veracrypt executable, this is set automatically if None.
    On Windows there are two different executables, one is used for creation and the other for
    mounting and dismounting, so the veracrypt_path should be the directory where these executables
    exist. On Linux and MacOS this should be the full path to the veracrypt program.

    **WARNING:** On Windows the VeraCrypt CLI does not allow the passing of the password via stdin 
    which means that the subprocess call could expose the password in logs or history. The password
    is sanitized in the args of the subprocess.CompletedProcess returned value so that if it is
    printed or logged the password will not be exposed. 
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
        """
        Mounts a VeraCrypt volume.
        :param volume_path: the path to the volume to be mounted
        :param password: the password for the volume
        :param mount_point: the mount point where to mount the volume
        :param options: any additional options that should be passed. Be careful when 
        using these options there will be diffences based on platform.
        :return: a subprocess.CompletedProcess response from the command line
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
        """
        Dismounts a VeraCrypt volume.
        :param target: the mount point to dismount, default is all which will dismount all mounted volumes.
        :return: a subprocess.CompletedProcess response from the command line
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
        """
        Creates a VeraCrypt volume.
        :param volume_path: the path to the volume to be mounted
        :param password: the password for the volume
        :param size: the size of the volume in bytes
        :param encryption: the encryption type to use to encrypt the volume
        :param hash_alg: the hash algorithm to use to encrypt the volume
        :param filesystem: the formatting to use to format the volume
        :param keyfiles: the keyfiles that should be used to encrypt the volume
        :param hidden: a bool for whether the volume should be a hidden volume
        :return: a subprocess.CompletedProcess response from the command line
        """
        self.logger.debug('Creating volume')

        if self.os_name == 'Windows':
            cmd = self._create_win(volume_path, password, size, encryption, hash_alg, filesystem, keyfiles)
        else:
            if self.os_name == 'Darwin':
                if not os.path.exists(volume_path):
                    with open(volume_path, 'w'): pass
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
        """
        Calls the VeraCrypt CLI with the given options.
        :param options: the options to be passed to the VeraCrypt CLI
        :param windows_program: Windows Only option for a which program to call 
        :return: a subprocess.CompletedProcess response from the command line
        """
        self.logger.debug('Calling custom command')
        password, index = self._get_password(options)

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
        self.logger.debug('Calling custom command on Windows')
        cmd = [os.path.join(self.veracrypt_path, windows_program)]
        
        if options:
            cmd += options
        self.logger.debug('Custom command generated')
        return cmd
    
    def _custom_nix(self, options: Optional[List[str]] = None) -> List[str]:
        self.logger.debug('Calling custom command on Linux/MacOS')
        password, p_index = self._get_password(options)
        cmd = ['sudo', self.veracrypt_path]

        if password:
            self.logger.debug('Removing password from command line options')
            del options[p_index -1:p_index + 1]
        
        if options:
            cmd += options
        
        if password:
            if '--stdin' not in options:
                cmd += '--stdin'
        self.logger.debug('Custom command generated')
        return cmd
    
    def _get_password(self, cmd: List[str]) -> Tuple[str, int]:
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
