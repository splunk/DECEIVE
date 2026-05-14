from configparser import ConfigParser
from pathlib import Path
import re

from deceive.config import discover_protocol_instances


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_configuration_reference_ini_blocks_parse():
    docs = (REPO_ROOT / "docs" / "configuration.md").read_text()
    blocks = re.findall(r"```ini\n(.*?)\n```", docs, flags=re.DOTALL)

    assert blocks
    for block in blocks:
        config = ConfigParser()
        config.read_string(block)


def test_top_level_template_parses_and_uses_disabled_protocol_defaults():
    config = ConfigParser()
    config.read(REPO_ROOT / "config.ini.TEMPLATE")

    instances = discover_protocol_instances(config)
    by_name = {instance.full_name: instance for instance in instances}

    assert by_name["ssh:main"].enabled is True
    assert by_name["http:marketing"].enabled is False
    assert by_name["http:api"].enabled is False
    assert by_name["https:secure"].enabled is False


def test_legacy_ssh_template_normalizes_to_enabled_ssh_instance():
    config = ConfigParser()
    config.read(REPO_ROOT / "SSH" / "config.ini.TEMPLATE")

    instances = discover_protocol_instances(config)

    assert len(instances) == 1
    assert instances[0].full_name == "ssh:main"
    assert instances[0].enabled is True
    assert instances[0].legacy is True
