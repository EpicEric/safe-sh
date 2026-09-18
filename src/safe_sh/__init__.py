# safe-sh: Static shell script analysis with Jev
# Copyright (C) 2026 Eric Rodrigues Pires
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for
# more details.
#
# You should have received a copy of the GNU Affero General Public License along
# with this program. If not, see <https://www.gnu.org/licenses/>.

import argparse
import asyncio
import os
import sys

import tree_sitter_bash
from tree_sitter import Language, Parser
from typesafe_sdk import (
    AsyncTypeSafeClient,
    Score,
    ScoreAnswer,
)

# Every question rates a chunk on the same three-level scale:
#   level 0 - the behavior is absent
#   level 1 - the behavior is present, but it is benign or scoped to what the user asked
#   level 2 - the behavior is present in a way that is genuinely dangerous
QUESTIONS: dict[str, Score] = {
    "file_removal": Score(
        instructions="Does this block of shell script remove, overwrite, or corrupt user files (e.g. rm -rf, shred, dd to a device)?",
        criteria=[
            "The script does not delete, overwrite, or corrupt any files.",
            "The script deletes or overwrites only files it created itself or that belong to the tool the user is installing, such as clearing its own cache, build, or temp directory, or replacing an older version of the same package.",
            "The script deletes, overwrites, or corrupts user data or files it did not create, such as rm -rf on a home or user directory, shred, or dd writing to a disk or device.",
        ],
    ),
    "credential_theft": Score(
        instructions="Does this script search for, read, or exfiltrate credentials, API keys, SSH keys, browser cookies, or password manager files?",
        criteria=[
            "The script does not read or access credential, API key, SSH key, cookie, or password manager files.",
            "The script reads a local config or credential file only to configure the tool the user is installing (e.g. an existing git, npm, or package-manager config) and does not send it anywhere.",
            "The script reads credentials, SSH keys, browser cookies, or password manager files and sends them to a remote host, or collects them for exfiltration.",
        ],
    ),
    "data_exfiltration": Score(
        instructions="Does this script send local files, environment variables, or system data to a remote server via curl, wget, nc, or similar?",
        criteria=[
            "The script makes no network request that sends local data to a remote host.",
            "The script only sends data that is normal for the tool the user is installing (e.g. downloading a package or an opt-in telemetry ping) and does not send credentials, keys, or user files.",
            "The script sends local files, environment variables, or system data that may contain secrets to a remote server.",
        ],
    ),
    "reverse_shell": Score(
        instructions="Does this script open a network connection back to a remote host that grants interactive command execution (e.g. bash -i, nc -e, /dev/tcp redirection)?",
        criteria=[
            "The script does not open any network connection that grants remote command execution.",
            "The script opens a normal outbound connection the tool needs (e.g. downloading a package or calling its own API) but does not grant interactive or remote command execution.",
            "The script opens a connection that grants interactive or remote command execution, such as bash -i, nc -e, or /dev/tcp redirection to a shell.",
        ],
    ),
    "persistence": Score(
        instructions="Does this script set up anything to run automatically later, e.g. via cron, systemd units, shell rc files (.bashrc/.zshrc), or launch agents?",
        criteria=[
            "The script does not add any mechanism to run automatically later.",
            "The script registers a service or shell setting as part of installing the tool the user requested (e.g. brew services, a package that installs a systemd unit, or adding a PATH entry to a shell rc file), scoped to that tool.",
            "The script installs itself or another payload to run automatically later without the user's explicit request, such as a cron job, a hidden rc-file line, or a launch agent that runs an unrelated command.",
        ],
    ),
    "privilege_escalation": Score(
        instructions="Does this script attempt to gain elevated privileges beyond what's needed, e.g. modifying sudoers, setting SUID bits, or exploiting kernel/service vulnerabilities?",
        criteria=[
            "The script does not attempt to gain elevated privileges.",
            "The script asks for or uses root/admin privileges that are normal for installing the requested tool (e.g. prompting for sudo to write to /usr/local) and nothing more.",
            "The script attempts to gain elevated privileges beyond what installing the tool needs, such as modifying sudoers, setting SUID bits, or exploiting a kernel or service vulnerability.",
        ],
    ),
    "obfuscation": Score(
        instructions="Does this script use base64, hex encoding, eval, or other obfuscation to hide its actual behavior from a human reader?",
        criteria=[
            "The script is plain, readable shell and does not use base64, hex, eval, or other encoding to hide behavior.",
            "The script uses encoding or complex logic that is standard for a well-known installer (e.g. embedded version strings, checksums, or bundled installer data) and does not conceal what it does from a human reader.",
            "The script uses base64, hex, eval, or similar to actively conceal its behavior so a human reader cannot tell what it does.",
        ],
    ),
    "silent_download_execute": Score(
        instructions="Does this script download a second-stage payload from a URL and execute it without any visible indication to the user?",
        criteria=[
            "The script does not download and execute a payload from a URL.",
            "The script downloads and runs the tool the user is installing from its official source, with visible output indicating what is being downloaded and installed.",
            "The script downloads a second-stage payload from a URL and executes it without any visible indication to the user.",
        ],
    ),
    "disabling_defenses": Score(
        instructions="Does this script disable or tamper with antivirus, firewall, logging, or update mechanisms?",
        criteria=[
            "The script does not touch antivirus, firewall, logging, or update mechanisms.",
            "The script configures or updates security tooling as part of the requested install (e.g. installing a firewall package the user asked for) without disabling protections.",
            "The script disables or tampers with antivirus, firewall, logging, or update mechanisms.",
        ],
    ),
    "cryptomining": Score(
        instructions="Does this script download and run a cryptocurrency mining binary or connect to a mining pool?",
        criteria=[
            "The script does not download or run a cryptocurrency miner or connect to a mining pool.",
            "The script downloads and runs a legitimate, compute-heavy tool the user requested that is not a miner and does not connect to a mining pool.",
            "The script downloads and runs a cryptocurrency mining binary or connects to a mining pool.",
        ],
    ),
    "supply_chain_tampering": Score(
        instructions="Does this script modify package manager configs, add untrusted repositories, or replace legitimate binaries/aliases with malicious ones?",
        criteria=[
            "The script does not modify package manager configs, add repositories, or replace binaries or aliases.",
            "The script modifies package manager config as part of the requested install (e.g. adding the official repository for the tool the user is installing) using a trusted source.",
            "The script adds an untrusted repository, or replaces a legitimate binary, alias, or package-manager config with a malicious one.",
        ],
    ),
    "environment_scraping": Score(
        instructions="Does this script dump environment variables, shell history, or config files that might contain secrets?",
        criteria=[
            "The script does not dump environment variables, shell history, or config files.",
            "The script reads its own environment or a config file only to configure the requested tool (e.g. reading PATH or a tool's config) and does not dump or send it.",
            "The script dumps environment variables, shell history, or config files that may contain secrets, or sends them elsewhere.",
        ],
    ),
    "network_scanning": Score(
        instructions="Does this script scan the local network, enumerate other hosts, or attempt lateral movement?",
        criteria=[
            "The script does not scan the local network, enumerate hosts, or attempt lateral movement.",
            "The script makes a normal network request the requested tool needs (e.g. reaching its own API or a package mirror) but does not scan or enumerate other hosts.",
            "The script scans the local network, enumerates other hosts, or attempts lateral movement.",
        ],
    ),
    "destructive_fork_bomb": Score(
        instructions="Does this script contain a fork bomb or resource-exhaustion pattern intended to crash or degrade the system?",
        criteria=[
            "The script contains no fork bomb or resource-exhaustion pattern.",
            "The script does work that is compute- or memory-intensive but bounded and normal for the requested install (e.g. compiling a package), not intended to crash the system.",
            "The script contains a fork bomb or resource-exhaustion pattern intended to crash or degrade the system.",
        ],
    ),
    "unverified_checksum": Score(
        instructions="Does this script download binaries or scripts without verifying a checksum or signature against a trusted source?",
        criteria=[
            "The script does not download any binaries or scripts.",
            "The script downloads binaries or scripts from the official source of the well-known tool the user is installing (e.g. rustup.rs or a package mirror), whether or not it verifies a checksum.",
            "The script downloads binaries or scripts from an untrusted or obscure source without verifying a checksum or signature.",
        ],
    ),
}


async def analyze_chunk(
    client: AsyncTypeSafeClient, running_as_superuser: bool, chunk: str
) -> tuple[list[str], dict[str, ScoreAnswer]]:
    response = await client.system_one(
        state={"script": chunk, "running_as_superuser": running_as_superuser},
        questions=QUESTIONS,
    )
    return (chunk.splitlines(), response.scores)


def get_chunks(script: str, max_size: int = 16384) -> list[str]:
    parser = Parser(Language(tree_sitter_bash.language()))
    tree = parser.parse(bytes(script, encoding="utf-8"))
    result = []

    stack = list(tree.root_node.children)
    while stack:
        node = stack.pop(0)
        if not node.text or node.type == "comment":
            continue
        if len(node.text) >= max_size and node.child_count > 0:
            stack = list(node.children) + stack
        else:
            result.append(node.text.decode("utf-8")[:max_size])

    return result


async def run(script: str, warn_on: float, error_on: float, short: bool) -> None:
    running_as_superuser = os.getuid() == 0
    async with AsyncTypeSafeClient() as client:
        chunks = await asyncio.gather(
            *(
                analyze_chunk(client, running_as_superuser, chunk)
                for chunk in get_chunks(script)
            )
        )

    errors = 0
    start_line = 1
    for chunk_lines, answer in chunks:
        chunk_is_safe = True
        lines = len(chunk_lines)
        end_line = start_line + lines - 1

        for key, value in answer.items():
            top_level = len(QUESTIONS[key].criteria) - 1
            score = value.score / top_level
            if score >= 0.8:
                log_line = (
                    f"'{key}' rule detected on lines {start_line}-{end_line}"
                    if end_line > start_line
                    else f"'{key}' rule detected on line {start_line}"
                )
                if value.confidence >= error_on:
                    chunk_is_safe = False
                    print(
                        f"[ERROR (p={value.confidence} score={score})] {log_line}",
                        file=sys.stderr,
                    )
                elif value.confidence >= warn_on:
                    print(
                        f"[WARN  (p={value.confidence} score={score})] {log_line}",
                        file=sys.stderr,
                    )

        if not chunk_is_safe:
            errors += 1
            if not short:
                for i, line in enumerate(chunk_lines):
                    print(f"  | {start_line + i:>5} | {line}", file=sys.stderr)
                print()

        start_line = end_line + 1

    if errors:
        print(
            f"{errors} {'errors' if errors > 1 else 'error'} raised. Review the script carefully",
            file=sys.stderr,
        )
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(prog="safe-sh")
    parser.add_argument(
        "-c",
        help="script to analyze",
        type=str,
    )
    parser.add_argument(
        "--warn-on",
        help="at which confidence threshold to show warnings",
        type=float,
        default=0.33,
    )
    parser.add_argument(
        "--error-on",
        help="at which confidence threshold to trigger errors",
        type=float,
        default=0.5,
    )
    parser.add_argument(
        "--short",
        help="print short logs",
        action="store_true",
    )
    args = parser.parse_args()

    asyncio.run(
        run(
            script=args.c or sys.stdin.read(),
            warn_on=args.warn_on,
            error_on=args.error_on,
            short=args.short,
        )
    )
