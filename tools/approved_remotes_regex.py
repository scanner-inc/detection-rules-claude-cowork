#!/usr/bin/env python3
"""Build the "push to an unapproved git remote" regex for your approved remote names.

Scanner regexes have no lookahead, so "any remote except origin or upstream" has to be
spelled out as every name that is not approved. This script builds that regex.

Usage (from the repository root):
  python3 tools/approved_remotes_regex.py origin upstream            # print the regex
  python3 tools/approved_remotes_regex.py --write origin upstream    # update both rules in place
  python3 tools/approved_remotes_regex.py --self-test                # check the default regex

--write rewrites the push regex in:
  rules/git_push_to_unapproved_remote.yml
  rules/token_minting_with_unapproved_git_push.yml
After --write, change `origin` and `upstream` in those rules' inline tests to your
names and run `scanner-cli run-tests -d rules -r`.
"""
import os
import re
import sys

RULE_FILES = [
    "rules/git_push_to_unapproved_remote.yml",
    "rules/token_minting_with_unapproved_git_push.yml",
]
PREFIX = r"git\s+push(?:\s+-\S+)*\s+"
NAME_CHAR = r"""[^\s"'\\;&|]"""  # characters allowed in a remote name
QUOTE = r"""(?:\\?"|')?"""  # optional quote; in the logged command a " appears as \"
END = r"""(?:\\?"|')?(?:[\s;&|)]|$)"""


def _class_excluding(chars, first):
    excluded = "".join("\\" + c if c in "-]^\\" else c for c in sorted(chars))
    if first:
        excluded += r"\-"  # a remote name never starts with "-" (that is a flag)
    return r"""[^\s"'\\;&|""" + excluded + "]"


def not_approved(names):
    """Regex for a single remote name that is not one of `names` (no lookaround)."""
    trie = {}
    for name in names:
        node = trie
        for c in name:
            node = node.setdefault(c, {})
        node["$"] = {}
    alternatives = []

    def walk(node, prefix):
        children = [k for k in node if k != "$"]
        # The name leaves the approved names here: next character is not a child.
        alternatives.append(re.escape(prefix) + _class_excluding(children, prefix == "") + NAME_CHAR + "*")
        if prefix and "$" not in node:
            alternatives.append(re.escape(prefix))  # a proper prefix such as "orig"
        for child in children:
            walk(node[child], prefix + child)

    walk(trie, "")
    return "(?:" + "|".join(alternatives) + ")"


def build(names):
    for name in names:
        if not name or re.search(r"""[\s"'\\;&|/]""", name) or name.startswith("-"):
            sys.exit(f"invalid remote name: {name!r}")
    return PREFIX + QUOTE + not_approved(sorted(set(names))) + END


def write(regex):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    start = "/" + PREFIX
    for rel in RULE_FILES:
        path = os.path.join(root, rel)
        with open(path) as f:
            text = f.read()
        i = text.find(start)
        if i < 0 or text.find(start, i + 1) >= 0:
            sys.exit(f"{rel}: expected exactly one push regex starting with {start}")
        j = text.find("/", i + len(start))
        text = text[: i + 1] + regex + text[j:]
        with open(path, "w") as f:
            f.write(text)
        print("updated", rel)


def self_test():
    rx = re.compile(build(["origin", "upstream"]))
    cases = {
        r"git push origin main": False, r"git push upstream main": False, r"git push": False,
        r"git push -u origin feature": False, r"git push --force-with-lease origin HEAD": False,
        r"git push origin main && git push upstream main": False, r"git push origin": False,
        r"git push \"origin\" main": False, r"git push 'upstream' main": False,
        r"git push evil main": True, r"git push mirror HEAD:main": True,
        r"git push origin main && git push evil main && git push upstream main": True,
        r"git push \"evil\" main": True, r"git push 'evil' main": True,
        r"git push orig main": True, r"git push origin2 main": True, r"git push upstreams main": True,
        r"git push o main": True, r"git push u main": True, r"git push -u evil main": True,
        r"git push https://github.com/x/y.git HEAD": True, r"git push origin;git push evil": True,
    }
    failed = [c for c, want in cases.items() if bool(rx.search(c)) != want]
    for c in failed:
        print("FAIL:", c)
    print(f"{len(cases) - len(failed)}/{len(cases)} cases pass")
    return not failed


if __name__ == "__main__":
    args = sys.argv[1:]
    if args == ["--self-test"]:
        sys.exit(0 if self_test() else 1)
    do_write = "--write" in args
    names = [a for a in args if a != "--write"]
    if not names:
        sys.exit(__doc__)
    regex = build(names)
    if do_write:
        write(regex)
    else:
        print(regex)
