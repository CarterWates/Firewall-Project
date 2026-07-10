from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class NftCommandResult:
    """Result from an nftables command."""

    command: list[str]
    returncode: int
    stdout: str
    stderr: str


NftRunner = Callable[[list[str], str | None], NftCommandResult]


class NftablesClient:
    """Small nftables command wrapper with injectable execution for tests."""

    def __init__(
        self,
        *,
        binary: str = "nft",
        runner: NftRunner | None = None,
    ) -> None:
        self._binary = binary
        self._runner = runner or self._run_subprocess

    def list_ruleset(self) -> NftCommandResult:
        return self._runner([self._binary, "list", "ruleset"], None)

    def check_ruleset(self, ruleset: str) -> NftCommandResult:
        return self._runner([self._binary, "--check", "--file", "-"], ruleset)

    @staticmethod
    def _run_subprocess(command: list[str], input_text: str | None) -> NftCommandResult:
        completed = subprocess.run(
            command,
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
        )
        return NftCommandResult(
            command=command,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
