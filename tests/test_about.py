import re

from veracrypt import __about__


def test_about_metadata_values():
    assert __about__.__title__ == "python-veracrypt"
    assert __about__.__description__
    assert __about__.__url__.startswith("https://")
    assert __about__.__author__
    assert __about__.__author_email__
    assert __about__.__license__


def test_about_version_format():
    assert re.match(r"^\d+\.\d+\.\d+$", __about__.__version__)
