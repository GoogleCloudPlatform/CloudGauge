#!/usr/bin/env python3
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""The release's section of RELEASE_NOTES.md — the body of its GitHub Release (.github/workflows/release.yml, v20).

    python tools/release_notes.py v20.0.0      # the section headed "## v20.0.0 — …"
    python tools/release_notes.py v19.3.0      # "## v19.3 — …": the tags of the releases before v20 carry the ".0"s their headings lack

Prints the heading's title as a heading, then the section's text up to the next release's heading (or the roadmap).
Exits 1 with a message when no section carries the version — the release workflow stops there, so a tag never
publishes a release without its notes.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
NOTES = ROOT / "RELEASE_NOTES.md"
HEADING = re.compile(r"^## v(?P<version>\S+) — (?P<title>.+?)\s*$")


def normalised(version):
    """``v19.3`` → ``19.3.0``, ``20.0.0-rc.1`` stays ``20.0.0-rc.1``: what a tag and a heading have in common."""
    version = version.strip().removeprefix("v")
    core, _, suffix = version.partition("-")
    parts = core.split(".")
    while len(parts) < 3:
        parts.append("0")
    return ".".join(parts) + (f"-{suffix}" if suffix else "")


def section(text, version):
    """``(title, body)`` of the section of ``text`` headed with ``version``, or ``None``."""
    wanted = normalised(version)
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = HEADING.match(line)
        if match and normalised(match["version"]) == wanted:
            body = []
            for later in lines[index + 1:]:
                if later.startswith("## "):
                    break
                body.append(later)
            return match["title"], "\n".join(body).strip("\n")
    return None


def main(argv):
    if len(argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    found = section(NOTES.read_text(encoding="utf-8"), argv[1])
    if found is None:
        print(f"RELEASE_NOTES.md has no section headed '## v{normalised(argv[1])} — …' (or an equivalent shorter version): "
              f"write the release's notes before tagging it.", file=sys.stderr)
        return 1
    title, body = found
    print(f"## {title}\n\n{body}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
