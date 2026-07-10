from firewall_monitor.firewall.nft import NftablesClient, NftCommandResult


class RecordingRunner:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str], input_text: str | None) -> NftCommandResult:
        self.commands.append(command)
        return NftCommandResult(command=command, returncode=0, stdout="ok", stderr="")


def test_list_ruleset_builds_expected_command() -> None:
    runner = RecordingRunner()
    client = NftablesClient(runner=runner)

    result = client.list_ruleset()

    assert runner.commands == [["nft", "list", "ruleset"]]
    assert result.stdout == "ok"


def test_check_ruleset_uses_check_file_command() -> None:
    runner = RecordingRunner()
    client = NftablesClient(runner=runner)

    result = client.check_ruleset("table inet firewall_monitor {}\n")

    assert runner.commands == [["nft", "--check", "--file", "-"]]
    assert result.returncode == 0
