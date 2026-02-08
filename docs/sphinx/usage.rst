Usage
=====

Basic usage mirrors the VeraCrypt CLI and requires the VeraCrypt application to be
installed on your system.

.. code-block:: python

   from veracrypt import VeraCrypt, FileSystem
   import os

   vc = VeraCrypt()
   volume_path = os.path.join("C:\\", "Users", "user", "Desktop", "test.vc")

   # Create a volume
   vc.create_volume(volume_path, "SecretPassword", 5 * 1024 * 1024, filesystem=FileSystem.EXFAT)

   # Mount a volume
   vc.mount_volume(volume_path, "SecretPassword", "H", options=["/beep"])

   # Dismount a volume
   vc.dismount_volume("H", options=["/beep"])

   # Custom command
   vc.command([
       "/volume", volume_path, "/letter", "H", "/password", "SecretPassword",
       "/beep", "/quit", "/silent", "/force",
   ])
