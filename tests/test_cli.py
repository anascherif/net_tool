"""CLI wiring tests."""

from typer.main import get_command

from erreetool import cli


def test_cli_builds_command_tree():
    """CLI command tree should build without Typer/Click option errors."""
    command = get_command(cli.app)
    assert command.name == "erreetool"
