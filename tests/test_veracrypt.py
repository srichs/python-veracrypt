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
