import os
import subprocess
import unittest
from unittest.mock import MagicMock, patch

from veracrypt import Encryption, FileSystem, Hash, VeraCrypt, VeraCryptError


class TestVeraCrypt(unittest.TestCase):
    def setUp(self):
        self.veracrypt = VeraCrypt(veracrypt_path="/usr/bin/veracrypt")

    @patch("os.path.exists", return_value=True)
    def test_check_path_valid(self, mock_exists):
        self.assertTrue(
            self.veracrypt._check_path(
                os.path.join("C:\\", "Program Files", "VeraCrypt", "VeraCrypt.exe")
            )
        )

    @patch("os.path.exists", return_value=False)
    def test_check_path_invalid(self, mock_exists):
        with self.assertRaises(VeraCryptError):
            self.veracrypt._check_path(os.path.join("C:\\", "Program Files", "vc"))

    @patch("subprocess.run")
    @patch("os.path.exists", return_value=True)
    def test_mount_volume_linux(self, mock_exists, mock_run):
        self.veracrypt.os_name = "Linux"
        mock_run.return_value = MagicMock(returncode=0, stdout="Mounted")
        result = self.veracrypt.mount_volume("/vol", "pass")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Mounted", result.stdout)

    @patch("subprocess.run")
    @patch("os.path.exists", return_value=True)
    def test_dismount_volume_windows(self, mock_exists, mock_run):
        self.veracrypt.os_name = "Windows"
        mock_run.return_value = MagicMock(returncode=0, stdout="Dismounted")
        result = self.veracrypt.dismount_volume("Z")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Dismounted", result.stdout)

    @patch("subprocess.run")
    @patch("os.path.exists", return_value=True)
    def test_create_volume_default_params(self, mock_exists, mock_run):
        self.veracrypt.os_name = "Linux"
        mock_run.return_value = MagicMock(returncode=0, stdout="Created")
        result = self.veracrypt.create_volume("/vol", "pass", 1024)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Created", result.stdout)

    @patch("subprocess.run")
    def test_custom_command_error(self, mock_run):
        self.veracrypt.os_name = "Linux"
        mock_run.side_effect = subprocess.CalledProcessError(1, "cmd", stderr="Failed")
        with self.assertRaises(VeraCryptError):
            self.veracrypt.command(["--help"])

    @patch("subprocess.run")
    @patch("os.path.exists", return_value=True)
    def test_mount_volume_windows_masks_password(self, mock_exists, mock_run):
        self.veracrypt.os_name = "Windows"
        self.veracrypt.veracrypt_path = os.path.join(
            "C:\\", "Program Files", "VeraCrypt"
        )
        password = "SecretPassword"
        cmd = [
            os.path.join(self.veracrypt.veracrypt_path, "VeraCrypt.exe"),
            "/volume",
            "C:/vol",
            "/password",
            password,
            "/quit",
            "/silent",
            "/force",
        ]
        mock_run.return_value = subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout="OK", stderr=""
        )

        result = self.veracrypt.mount_volume("C:/vol", password)

        self.assertEqual(result.args[4], "*" * len(password))
        mock_run.assert_called_once()

    @patch("subprocess.run")
    def test_mount_volume_nix_uses_stdin(self, mock_run):
        self.veracrypt.os_name = "Linux"
        self.veracrypt.veracrypt_path = "/usr/bin/veracrypt"
        password = "secret"
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="OK", stderr=""
        )

        with patch.object(self.veracrypt, "_check_path", return_value=True):
            self.veracrypt.mount_volume("/vol", password, mount_point="/mnt")

        mock_run.assert_called_once()
        _, kwargs = mock_run.call_args
        self.assertEqual(kwargs.get("input"), f"{password}\n")

    def test_custom_nix_removes_password_and_adds_stdin(self):
        self.veracrypt.os_name = "Linux"
        self.veracrypt.veracrypt_path = "/usr/bin/veracrypt"
        options = ["--text", "--password", "secret", "--mount", "/vol"]

        cmd = self.veracrypt._custom_nix(options)

        self.assertNotIn("secret", cmd)
        self.assertNotIn("--password", cmd)
        self.assertIn("--stdin", cmd)
        self.assertIn("--mount", cmd)

    @patch("subprocess.run")
    def test_custom_command_windows_masks_password(self, mock_run):
        self.veracrypt.os_name = "Windows"
        self.veracrypt.veracrypt_path = os.path.join(
            "C:\\", "Program Files", "VeraCrypt"
        )
        options = ["/volume", "C:/vol", "/password", "Secret"]
        cmd = [os.path.join(self.veracrypt.veracrypt_path, "VeraCrypt.exe")] + options
        mock_run.return_value = subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout="OK", stderr=""
        )

        result = self.veracrypt.command(options)

        self.assertEqual(result.args[4], "*" * len("Secret"))

    def test_dismount_nix_checks_target_path(self):
        self.veracrypt.os_name = "Linux"
        self.veracrypt.veracrypt_path = "/usr/bin/veracrypt"

        with patch.object(
            self.veracrypt, "_check_path", return_value=True
        ) as mock_check:
            cmd = self.veracrypt._dismount_nix("/mnt/vol")

        mock_check.assert_called_once_with("/mnt/vol")
        self.assertIn("/mnt/vol", cmd)

    def test_create_win_includes_keyfiles_and_options(self):
        self.veracrypt.os_name = "Windows"
        self.veracrypt.veracrypt_path = os.path.join(
            "C:\\", "Program Files", "VeraCrypt"
        )
        cmd = self.veracrypt._create_win(
            "C:/vol",
            "Secret",
            1024,
            encryption=Encryption.SERPENT,
            hash_alg=Hash.WHIRLPOOL,
            filesystem=FileSystem.NTFS,
            keyfiles=["C:/key1", "C:/key2"],
            options=["/random", "/extra"],
        )

        self.assertIn("/keyfile", cmd)
        self.assertIn("C:/key1", cmd)
        self.assertIn("C:/key2", cmd)
        self.assertIn("/random", cmd)
        self.assertIn("/extra", cmd)
        self.assertIn("Serpent", cmd)
        self.assertIn("whirlpool", cmd)
        self.assertIn("NTFS", cmd)

    def test_create_nix_hidden_volume(self):
        self.veracrypt.os_name = "Linux"
        self.veracrypt.veracrypt_path = "/usr/bin/veracrypt"
        cmd = self.veracrypt._create_nix(
            "/vol",
            1024,
            encryption=Encryption.AES_TWOFISH,
            hash_alg=Hash.SHA256,
            filesystem=FileSystem.EXT4,
            keyfiles=["/tmp/keyfile"],
            hidden=True,
            options=["--random-source", "/dev/random"],
        )

        self.assertIn("--volume-type", cmd)
        self.assertIn("hidden", cmd)
        self.assertIn("--keyfiles", cmd)
        self.assertIn("/tmp/keyfile", cmd)
        self.assertIn("--random-source", cmd)
        self.assertIn("/dev/random", cmd)
        self.assertIn("AES(Twofish)", cmd)
        self.assertIn("sha-256", cmd)
        self.assertIn("ext4", cmd)

    def test_default_path_linux_uses_check_path(self):
        self.veracrypt.os_name = "Linux"
        with patch.object(self.veracrypt, "_check_path", return_value=True) as mock:
            path = self.veracrypt._default_path()

        self.assertEqual(path, os.path.join("/", "usr", "bin", "veracrypt"))
        mock.assert_called_once_with(path)

    @patch("os.path.exists", return_value=False)
    def test_default_path_windows_missing_binary_raises(self, mock_exists):
        self.veracrypt.os_name = "Windows"

        with self.assertRaises(VeraCryptError):
            self.veracrypt._default_path()

    @patch("os.path.exists", side_effect=[True, False])
    def test_default_path_windows_missing_format_binary_raises(self, mock_exists):
        self.veracrypt.os_name = "Windows"

        with self.assertRaises(VeraCryptError) as ctx:
            self.veracrypt._default_path()

        self.assertIn("VeraCrypt Format.exe", str(ctx.exception))

    def test_default_path_darwin_uses_check_path(self):
        self.veracrypt.os_name = "Darwin"
        with patch.object(self.veracrypt, "_check_path", return_value=True) as mock:
            path = self.veracrypt._default_path()

        self.assertIn("VeraCrypt.app", path)
        mock.assert_called_once_with(path)

    def test_get_password_windows(self):
        self.veracrypt.os_name = "Windows"
        password, index = self.veracrypt._get_password(
            [
                "/volume",
                "C:/vol",
                "/password",
                "Secret",
            ]
        )

        self.assertEqual(password, "Secret")
        self.assertEqual(index, 3)

    def test_get_password_missing_returns_none(self):
        self.veracrypt.os_name = "Linux"
        password, index = self.veracrypt._get_password(["--text", "--mount", "/vol"])

        self.assertIsNone(password)
        self.assertEqual(index, -1)

    def test_get_password_none_command_returns_none(self):
        self.veracrypt.os_name = "Linux"
        password, index = self.veracrypt._get_password(None)

        self.assertIsNone(password)
        self.assertEqual(index, -1)

    def test_get_password_empty_value_raises(self):
        self.veracrypt.os_name = "Linux"

        with self.assertRaises(ValueError) as ctx:
            self.veracrypt._get_password(
                ["--text", "--password", "", "--mount", "/vol"]
            )

        self.assertIn("without a value", str(ctx.exception))

    def test_custom_nix_without_password_skips_stdin(self):
        self.veracrypt.os_name = "Linux"
        self.veracrypt.veracrypt_path = "/usr/bin/veracrypt"
        options = ["--text", "--mount", "/vol"]

        cmd = self.veracrypt._custom_nix(options)

        self.assertNotIn("--stdin", cmd)
        self.assertIn("--text", cmd)

    def test_mount_win_includes_letter_and_options(self):
        self.veracrypt.os_name = "Windows"
        self.veracrypt.veracrypt_path = os.path.join(
            "C:\\", "Program Files", "VeraCrypt"
        )

        cmd = self.veracrypt._mount_win(
            "C:/vol", "Secret", mount_point="X", options=["/readonly"]
        )

        self.assertIn("/letter", cmd)
        self.assertIn("X", cmd)
        self.assertIn("/readonly", cmd)
        self.assertEqual(cmd[-3:], ["/quit", "/silent", "/force"])

    def test_mount_nix_includes_mount_point_and_options(self):
        self.veracrypt.os_name = "Linux"
        self.veracrypt.veracrypt_path = "/usr/bin/veracrypt"

        cmd = self.veracrypt._mount_nix(
            "/vol", mount_point="/mnt/vol", options=["--pim", "123"]
        )

        self.assertIn("/mnt/vol", cmd)
        self.assertIn("--pim", cmd)
        self.assertIn("123", cmd)
        self.assertIn("--stdin", cmd)
        self.assertIn("--force", cmd)

    def test_options_validation_rejects_non_list(self):
        self.veracrypt.os_name = "Linux"
        self.veracrypt.veracrypt_path = "/usr/bin/veracrypt"

        with self.assertRaises(ValueError):
            self.veracrypt.mount_volume("/vol", "secret", options="--pim 123")

    def test_custom_nix_keeps_existing_stdin(self):
        self.veracrypt.os_name = "Linux"
        self.veracrypt.veracrypt_path = "/usr/bin/veracrypt"
        options = ["--text", "--password", "secret", "--mount", "/vol", "--stdin"]

        cmd = self.veracrypt._custom_nix(options)

        self.assertNotIn("secret", cmd)
        self.assertNotIn("--password", cmd)
        self.assertEqual(cmd.count("--stdin"), 1)

    @patch("subprocess.run")
    def test_command_linux_password_uses_stdin(self, mock_run):
        self.veracrypt.os_name = "Linux"
        self.veracrypt.veracrypt_path = "/usr/bin/veracrypt"
        options = ["--text", "--password", "secret", "--mount", "/vol"]
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="OK", stderr=""
        )

        self.veracrypt.command(options)

        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        self.assertNotIn("secret", args[0])
        self.assertEqual(kwargs.get("input"), "secret\n")

    def test_custom_win_appends_options(self):
        self.veracrypt.os_name = "Windows"
        self.veracrypt.veracrypt_path = os.path.join(
            "C:\\", "Program Files", "VeraCrypt"
        )
        options = ["/volume", "C:/vol", "/quit"]

        cmd = self.veracrypt._custom_win(options, windows_program="VeraCrypt.exe")

        self.assertEqual(
            cmd[0], os.path.join(self.veracrypt.veracrypt_path, "VeraCrypt.exe")
        )
        self.assertEqual(cmd[1:], options)

    def test_custom_nix_without_options_returns_base_command(self):
        self.veracrypt.os_name = "Linux"
        self.veracrypt.veracrypt_path = "/usr/bin/veracrypt"

        cmd = self.veracrypt._custom_nix()

        self.assertEqual(cmd, ["sudo", "/usr/bin/veracrypt"])

    def test_dismount_nix_all_skips_check_path(self):
        self.veracrypt.os_name = "Linux"
        self.veracrypt.veracrypt_path = "/usr/bin/veracrypt"

        with patch.object(self.veracrypt, "_check_path") as mock_check:
            cmd = self.veracrypt._dismount_nix()

        mock_check.assert_not_called()
        self.assertIn("--unmount", cmd)

    @patch("subprocess.run")
    def test_create_volume_windows_masks_password(self, mock_run):
        self.veracrypt.os_name = "Windows"
        self.veracrypt.veracrypt_path = os.path.join(
            "C:\\", "Program Files", "VeraCrypt"
        )
        password = "SecretPassword"
        cmd = [
            os.path.join(self.veracrypt.veracrypt_path, "VeraCrypt Format.exe"),
            "/create",
            "C:/vol",
            "/password",
            password,
            "/size",
            "1024",
            "/encryption",
            "AES",
            "/hash",
            "sha-512",
            "/filesystem",
            "FAT",
            "/protectMemory",
            "/quick",
            "/silent",
            "/force",
        ]
        mock_run.return_value = subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout="OK", stderr=""
        )

        result = self.veracrypt.create_volume("C:/vol", password, 1024)

        self.assertEqual(result.args[4], "*" * len(password))

    @patch("subprocess.run")
    def test_command_linux_without_password_avoids_stdin(self, mock_run):
        self.veracrypt.os_name = "Linux"
        self.veracrypt.veracrypt_path = "/usr/bin/veracrypt"
        options = ["--text", "--mount", "/vol"]
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="OK", stderr=""
        )

        self.veracrypt.command(options)

        _, kwargs = mock_run.call_args
        self.assertIsNone(kwargs.get("input"))

    @patch("subprocess.run")
    def test_dismount_volume_windows_error_raises(self, mock_run):
        self.veracrypt.os_name = "Windows"
        mock_run.side_effect = subprocess.CalledProcessError(1, "cmd", stderr="Oops")

        with self.assertRaises(VeraCryptError) as ctx:
            self.veracrypt.dismount_volume("Z")

        self.assertIn("Oops", str(ctx.exception))

    @patch("subprocess.run")
    def test_mount_volume_windows_error_raises(self, mock_run):
        self.veracrypt.os_name = "Windows"
        mock_run.side_effect = subprocess.CalledProcessError(1, "cmd", stderr="Nope")

        with (
            patch.object(self.veracrypt, "_check_path", return_value=True),
            self.assertRaises(VeraCryptError) as ctx,
        ):
            self.veracrypt.mount_volume("C:/vol", "Secret")

        self.assertIn("Nope", str(ctx.exception))

    @patch("subprocess.run")
    def test_create_volume_linux_error_raises(self, mock_run):
        self.veracrypt.os_name = "Linux"
        self.veracrypt.veracrypt_path = "/usr/bin/veracrypt"
        mock_run.side_effect = subprocess.CalledProcessError(1, "cmd", stderr="Bad")

        with self.assertRaises(VeraCryptError) as ctx:
            self.veracrypt.create_volume("/vol", "secret", 1024)

        self.assertIn("Bad", str(ctx.exception))

    @patch("subprocess.run")
    def test_create_volume_windows_passes_options(self, mock_run):
        self.veracrypt.os_name = "Windows"
        self.veracrypt.veracrypt_path = os.path.join(
            "C:\\", "Program Files", "VeraCrypt"
        )
        cmd = [
            os.path.join(self.veracrypt.veracrypt_path, "VeraCrypt Format.exe"),
            "/create",
            "C:/vol",
            "/password",
            "Secret",
            "/size",
            "1024",
            "/encryption",
            "AES",
            "/hash",
            "sha-512",
            "/filesystem",
            "FAT",
        ]
        mock_run.return_value = subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout="OK", stderr=""
        )

        with patch.object(self.veracrypt, "_create_win", return_value=cmd) as mock:
            self.veracrypt.create_volume(
                "C:/vol", "Secret", 1024, options=["/random", "/extra"]
            )

        mock.assert_called_once_with(
            "C:/vol",
            "Secret",
            1024,
            Encryption.AES,
            Hash.SHA512,
            FileSystem.FAT,
            None,
            ["/random", "/extra"],
        )

    @patch("subprocess.run")
    def test_create_volume_linux_passes_options(self, mock_run):
        self.veracrypt.os_name = "Linux"
        self.veracrypt.veracrypt_path = "/usr/bin/veracrypt"
        mock_run.return_value = subprocess.CompletedProcess(
            args=["cmd"], returncode=0, stdout="OK", stderr=""
        )

        with patch.object(self.veracrypt, "_create_nix", return_value=["cmd"]) as mock:
            self.veracrypt.create_volume(
                "/vol", "secret", 1024, options=["--random-source", "/dev/random"]
            )

        mock.assert_called_once_with(
            "/vol",
            1024,
            Encryption.AES,
            Hash.SHA512,
            FileSystem.FAT,
            None,
            False,
            ["--random-source", "/dev/random"],
        )

    @patch("subprocess.run")
    def test_command_windows_without_password_does_not_mask(self, mock_run):
        self.veracrypt.os_name = "Windows"
        self.veracrypt.veracrypt_path = os.path.join(
            "C:\\", "Program Files", "VeraCrypt"
        )
        options = ["/volume", "C:/vol", "/quit"]
        cmd = [os.path.join(self.veracrypt.veracrypt_path, "VeraCrypt.exe")] + options
        mock_run.return_value = subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout="OK", stderr=""
        )

        result = self.veracrypt.command(options)

        self.assertEqual(result.args, cmd)

    def test_default_path_unsupported_os_raises(self):
        self.veracrypt.os_name = "Solaris"

        with self.assertRaises(VeraCryptError):
            self.veracrypt._default_path()

    def test_create_volume_rejects_invalid_encryption_type(self):
        self.veracrypt.os_name = "Linux"

        with self.assertRaises(ValueError) as ctx:
            self.veracrypt.create_volume("/vol", "secret", 1024, encryption="AES")

        self.assertIn(
            "encryption must be an instance of Encryption", str(ctx.exception)
        )

    def test_create_volume_rejects_invalid_hash_type(self):
        self.veracrypt.os_name = "Linux"

        with self.assertRaises(ValueError) as ctx:
            self.veracrypt.create_volume("/vol", "secret", 1024, hash_alg="sha-512")

        self.assertIn("hash_alg must be an instance of Hash", str(ctx.exception))

    def test_create_volume_rejects_invalid_filesystem_type(self):
        self.veracrypt.os_name = "Linux"

        with self.assertRaises(ValueError) as ctx:
            self.veracrypt.create_volume("/vol", "secret", 1024, filesystem="FAT")

        self.assertIn(
            "filesystem must be an instance of FileSystem", str(ctx.exception)
        )

    @patch("subprocess.run")
    @patch("os.path.exists", return_value=False)
    def test_create_volume_darwin_creates_placeholder(self, mock_exists, mock_run):
        self.veracrypt.os_name = "Darwin"
        self.veracrypt.veracrypt_path = "/usr/bin/veracrypt"
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="OK", stderr=""
        )

        with (
            patch("builtins.open", unittest.mock.mock_open()) as mock_open,
            patch.object(self.veracrypt, "_create_nix", return_value=["cmd"]),
        ):
            self.veracrypt.create_volume("/vol", "pass", 1024)

        mock_open.assert_called_once_with("/vol", "w")

    @patch("subprocess.run")
    @patch("os.path.exists", return_value=True)
    def test_create_volume_darwin_skips_placeholder_when_exists(
        self, mock_exists, mock_run
    ):
        self.veracrypt.os_name = "Darwin"
        self.veracrypt.veracrypt_path = "/usr/bin/veracrypt"
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="OK", stderr=""
        )

        with (
            patch("builtins.open", unittest.mock.mock_open()) as mock_open,
            patch.object(self.veracrypt, "_create_nix", return_value=["cmd"]),
        ):
            self.veracrypt.create_volume("/vol", "pass", 1024)

        mock_open.assert_not_called()
