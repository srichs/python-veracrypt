"""Live integration test script for the VeraCrypt wrapper.

This module is used for live testing on a real system. It creates a test volume on
the user's desktop, make sure that you put in the correct username so that the path
to the desktop is valid. It includes sleep time of five seconds between each action
so that it can be observed. You should watch the desktop for the creation of the
"test.vc" volume, and you should watch the VeraCrypt program to ensure the volume is
mounted and dismounted as the action is performed.
"""

from time import sleep
import logging
import os
import secrets

from veracrypt import FileSystem, VeraCrypt

if __name__ == "__main__":
    try:
        vc = VeraCrypt(
            logging.DEBUG,
            log_fmt="%(asctime)s:%(levelname)s:%(module)s:%(funcName)s:%(message)s",
        )
        username = "user"
        volume_path = ""
        volume_name = f"test_{secrets.token_urlsafe(6)}.vc"
        print(f"The test volume name is {volume_name}")

        if vc.os_name == "Windows":
            volume_path = os.path.join(
                "C:\\", "Users", username, "Desktop", volume_name
            )
            result = vc.create_volume(
                volume_path,
                "SecretPassword",
                5 * 1024 * 1024,
                filesystem=FileSystem.EXFAT,
            )
            print(result)
            sleep(5)
            result = vc.mount_volume(
                volume_path, "SecretPassword", "H", options=["/beep"]
            )
            print(result)
            sleep(5)
            vc.dismount_volume("H", options=["/beep"])
            sleep(5)
            result = vc.command(
                [
                    "/volume",
                    volume_path,
                    "/letter",
                    "H",
                    "/password",
                    "SecretPassword",
                    "/beep",
                    "/quit",
                    "/silent",
                    "/force",
                ]
            )
            print(result)
            sleep(5)
            vc.dismount_volume("H", options=["/beep"])
        else:
            if vc.os_name == "Darwin":  # macOS
                volume_path = os.path.join(
                    "/", "Users", username, "Desktop", volume_name
                )
            elif vc.os_name == "Linux":
                volume_path = os.path.join(
                    "/", "home", username, "Desktop", volume_name
                )
            else:
                raise OSError("Unsupported Operating System")

            result = vc.create_volume(
                volume_path,
                "SecretPassword",
                5 * 1024 * 1024,
                filesystem=FileSystem.EXFAT,
            )
            print(result)
            sleep(5)
            result = vc.mount_volume(volume_path, "SecretPassword")
            print(result)
            sleep(5)
            vc.dismount_volume(volume_path)
            sleep(5)
            result = vc.command(
                [
                    "--text",
                    "--non-interactive",
                    "--mount",
                    volume_path,
                    "--password",
                    "SecretPassword",
                    "--stdin",
                    "--force",
                ]
            )
            print(result)
            sleep(5)
            vc.dismount_volume(volume_path)

        print(f"Checking for path {volume_path}")

        if os.path.exists(volume_path):
            try:
                os.remove(volume_path)
                print("Test volume removed.")
            except Exception as e:
                print(f"Error deleting volume: {e}")
    except Exception as e:
        print(f"Error: {e}")
