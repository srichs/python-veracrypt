from unittest.mock import patch, MagicMock
from veracrypt import VeraCrypt, VeraCryptError, Encryption, Hash, FileSystem
import os
import subprocess
import unittest


class TestVeraCrypt(unittest.TestCase):
    def setUp(self):
        self.veracrypt = VeraCrypt()

    @patch("os.path.exists", return_value=True)
    def test_check_path_valid(self, mock_exists):
        self.assertTrue(self.veracrypt._check_path(os.path.join('C:\\', 'Program Files', 'VeraCrypt', 'VeraCrypt.exe')))

    @patch("os.path.exists", return_value=False)
    def test_check_path_invalid(self, mock_exists):
        with self.assertRaises(VeraCryptError):
            self.veracrypt._check_path(os.path.join('C:\\', 'Program Files', 'vc'))

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
