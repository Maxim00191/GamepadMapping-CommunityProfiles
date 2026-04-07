#!/usr/bin/env python3
"""
Validates Gamepad Mapping profile JSON files against the same rules as the WPF app:
- ProfileValidator (semantic cross-references)
- TemplateKeyboardActionResolver (actionId / holdActionId resolution)
- TemplateStorageKey-style rules for templateCatalogFolder

Usage:
  python .scripts/validate_templates.py ./profiles
  python .scripts/validate_templates.py file1.json file2.json
  python .scripts/validate_templates.py . --warnings-as-errors
  python .scripts/validate_templates.py . --check-duplicate-profile-ids
  python .scripts/validate_templates.py . --check-duplicate-profile-ids \\
    --incremental-semantic-git 'origin/main...HEAD'

Exit code: 0 = ok, 1 = validation failed (or duplicate profile ids when enabled).

With --incremental-semantic-git, only JSON files changed in the given git diff get full
semantic validation. When combined with --check-duplicate-profile-ids, every template
file is still loaded for JSON syntax + global profileId uniqueness (unchanged files are
assumed semantically valid since the last full check on main).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

SKIP_DIR_PARTS_LOWER = frozenset(
    {
        "node_modules",
        ".git",
        ".github",
        ".scripts",
        "__pycache__",
        ".venv",
        "venv",
    }
)

VALID_ID_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")


def is_valid_id(value: str | None) -> bool:
    if value is None or not str(value).strip():
        return False
    return bool(VALID_ID_PATTERN.match(str(value).strip()))


def validate_catalog_folder(raw: str | None) -> list[str]:
    """Mirror TemplateStorageKey.ValidateSingleSegmentFolderForSave."""
    errors: list[str] = []
    s = (raw or "").strip()
    if not s:
        return errors
    if "/" in s or "\\" in s:
        errors.append(
            "templateCatalogFolder must be a single name (no path separators)."
        )
    if s in (".", ".."):
        errors.append("templateCatalogFolder cannot be '.' or '..'.")
    invalid = set('<>:"|?*')
    if any(c in invalid for c in s) or any(ord(c) < 32 for c in s):
        # Windows invalid filename chars subset; keep message generic
        errors.append("templateCatalogFolder contains invalid characters.")
    return errors


def mapping_action_type(m: dict[str, Any]) -> str:
    if m.get("radialMenu") is not None:
        return "RadialMenu"
    if m.get("templateToggle") is not None:
        return "TemplateToggle"
    if m.get("itemCycle") is not None:
        return "ItemCycle"
    return "Keyboard"


def keyboard_action_has_output(a: dict[str, Any]) -> bool:
    if (a.get("keyboardKey") or "").strip():
        return True
    if a.get("templateToggle") is not None:
        return True
    if a.get("radialMenu") is not None:
        return True
    if a.get("itemCycle") is not None:
        return True
    return False


def apply_resolver_errors(data: dict[str, Any]) -> list[str]:
    """Mirror TemplateKeyboardActionResolver.Apply — return errors instead of throwing."""
    errors: list[str] = []
    mappings = data.get("mappings")
    if mappings is None:
        data["mappings"] = []
        mappings = data["mappings"]
    if not isinstance(mappings, list):
        return ["'mappings' must be an array."]

    catalog = data.get("keyboardActions")
    if catalog is None or (isinstance(catalog, list) and len(catalog) == 0):
        for i, m in enumerate(mappings):
            if not isinstance(m, dict):
                errors.append(f"mappings[{i}] must be an object.")
                continue
            aid = (m.get("actionId") or "").strip()
            hid = (m.get("holdActionId") or "").strip()
            if aid:
                errors.append(
                    f"mappings[{i}]: references actionId '{aid}' but keyboardActions is missing or empty."
                )
            if hid:
                errors.append(
                    f"mappings[{i}]: references holdActionId '{hid}' but keyboardActions is missing or empty."
                )
        return errors

    if not isinstance(catalog, list):
        return ["'keyboardActions' must be an array."]

    id_map: dict[str, dict[str, Any]] = {}
    for j, a in enumerate(catalog):
        if not isinstance(a, dict):
            errors.append(f"keyboardActions[{j}] must be an object.")
            continue
        aid = (a.get("id") or "").strip()
        if not aid:
            errors.append(f"keyboardActions[{j}]: id is empty.")
            continue
        key = aid.casefold()
        if key in id_map:
            errors.append(f"Duplicate keyboardActions id '{aid}'.")
            continue
        id_map[key] = a

    for i, m in enumerate(mappings):
        if not isinstance(m, dict):
            errors.append(f"mappings[{i}] must be an object.")
            continue
        action_id = (m.get("actionId") or "").strip()
        hold_id = (m.get("holdActionId") or "").strip()
        if not action_id and not hold_id:
            continue

        if action_id:
            if (
                m.get("itemCycle") is not None
                or m.get("templateToggle") is not None
                or m.get("radialMenu") is not None
            ):
                errors.append(
                    f"mappings[{i}]: actionId cannot be used together with "
                    "itemCycle, templateToggle, or radialMenu on the same mapping."
                )
            else:
                defn = id_map.get(action_id.casefold())
                if defn is None:
                    errors.append(
                        f"mappings[{i}]: unknown keyboardActions id '{action_id}'."
                    )
                else:
                    k = (defn.get("keyboardKey") or "").strip()
                    if (
                        not k
                        and defn.get("templateToggle") is None
                        and defn.get("radialMenu") is None
                        and defn.get("itemCycle") is None
                    ):
                        errors.append(
                            f"mappings[{i}]: keyboardActions id '{action_id}' has no "
                            "keyboardKey, templateToggle, radialMenu, or itemCycle."
                        )

        if hold_id:
            if hold_id.casefold() not in id_map:
                errors.append(
                    f"mappings[{i}]: unknown keyboardActions id '{hold_id}' (holdActionId)."
                )

    return errors


def validate_profile_object(data: dict[str, Any], path: str) -> tuple[list[str], list[str]]:
    """Mirror ProfileValidator + catalog folder. Returns (errors, warnings)."""
    errors: list[str] = []
    warnings: list[str] = []

    errors.extend(validate_catalog_folder(data.get("templateCatalogFolder")))

    profile_id = (data.get("profileId") or "").strip()
    if not profile_id:
        errors.append("Profile ID is required.")

    tg = (data.get("templateGroupId") or "").strip()
    if not tg and (data.get("gameId") or "").strip():
        tg = (data.get("gameId") or "").strip()
    if tg and not is_valid_id(tg):
        errors.append(
            "Template Group ID (when set) contains invalid characters."
        )

    action_ids: set[str] = set()
    keyboard_actions = data.get("keyboardActions")
    if keyboard_actions is not None:
        if not isinstance(keyboard_actions, list):
            errors.append("'keyboardActions' must be an array.")
        else:
            for j, action in enumerate(keyboard_actions):
                if not isinstance(action, dict):
                    errors.append(f"keyboardActions[{j}] must be an object.")
                    continue
                aid = (action.get("id") or "").strip()
                if not aid:
                    errors.append("Keyboard Action ID cannot be empty.")
                elif aid.casefold() in {x.casefold() for x in action_ids}:
                    errors.append(f"Duplicate Keyboard Action ID: {aid}")
                else:
                    action_ids.add(aid)
                if not keyboard_action_has_output(action):
                    warnings.append(
                        f"Action '{aid or '?'}' has no output (KeyboardKey, TemplateToggle or RadialMenu)."
                    )

    radial_menu_ids: set[str] = set()
    radial_menus = data.get("radialMenus")
    if radial_menus is not None:
        if not isinstance(radial_menus, list):
            errors.append("'radialMenus' must be an array.")
        else:
            for j, rm in enumerate(radial_menus):
                if not isinstance(rm, dict):
                    errors.append(f"radialMenus[{j}] must be an object.")
                    continue
                rid = (rm.get("id") or "").strip()
                if not rid:
                    errors.append("Radial Menu ID cannot be empty.")
                elif rid.casefold() in {x.casefold() for x in radial_menu_ids}:
                    errors.append(f"Duplicate Radial Menu ID: {rid}")
                else:
                    radial_menu_ids.add(rid)
                items = rm.get("items")
                if items is None or (isinstance(items, list) and len(items) == 0):
                    warnings.append(f"Radial Menu '{rid or '?'}' has no items.")
                elif isinstance(items, list):
                    for k, item in enumerate(items):
                        if not isinstance(item, dict):
                            errors.append(
                                f"radialMenus[{j}].items[{k}] must be an object."
                            )
                            continue
                        i_aid = (item.get("actionId") or "").strip()
                        if i_aid and i_aid.casefold() not in {
                            x.casefold() for x in action_ids
                        }:
                            errors.append(
                                f"Radial Menu '{rid}' references unknown Action ID: {i_aid}"
                            )

    mappings = data.get("mappings")
    if mappings is None:
        errors.append("'mappings' is required.")
    elif not isinstance(mappings, list):
        errors.append("'mappings' must be an array.")
    else:
        for i, mapping in enumerate(mappings):
            if not isinstance(mapping, dict):
                errors.append(f"mappings[{i}] must be an object.")
                continue
            from_ = mapping.get("from")
            from_val = ""
            if isinstance(from_, dict):
                from_val = (from_.get("value") or "").strip()
            if not from_val:
                errors.append("Mapping has no input button/chord.")

            m_action = (mapping.get("actionId") or "").strip()
            if m_action:
                if m_action.casefold() not in {x.casefold() for x in action_ids}:
                    errors.append(
                        f"Mapping references unknown Action ID: {m_action}"
                    )
            elif mapping_action_type(mapping) == "Keyboard" and not (
                mapping.get("keyboardKey") or ""
            ).strip():
                label = from_val or "?"
                errors.append(
                    f"Mapping for '{label}' has no output key."
                )

            rm_b = mapping.get("radialMenu")
            if isinstance(rm_b, dict):
                rmid = (rm_b.get("radialMenuId") or "").strip()
                if rmid and rmid.casefold() not in {
                    x.casefold() for x in radial_menu_ids
                }:
                    label = from_val or "?"
                    errors.append(
                        f"Mapping for '{label}' references unknown Radial Menu: {rmid}"
                    )

    errors.extend(apply_resolver_errors(data))

    return errors, warnings


def load_json_file(file_path: Path) -> dict[str, Any]:
    text = file_path.read_text(encoding="utf-8-sig")
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}") from e
    if not isinstance(obj, dict):
        raise ValueError("Root JSON value must be an object.")
    return obj


def iter_json_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root] if root.suffix.lower() == ".json" else []
    files: list[Path] = []
    for p in sorted(root.rglob("*.json")):
        # 显式忽略 index.json，因为它是一个数组而不是模板对象
        if p.name.lower() == "index.json":
            continue
        parts = {n.lower() for n in p.parts}
        if parts & SKIP_DIR_PARTS_LOWER:
            continue
        files.append(p)
    return files


def find_git_root(start: Path) -> Path | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        return Path(out.stdout.strip()).resolve()
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return None


def is_null_git_object(sha: str) -> bool:
    s = (sha or "").strip()
    return not s or all(c == "0" for c in s)


def git_changed_paths(repo_root: Path, rev_args: list[str]) -> list[str] | None:
    cmd = [
        "git",
        "-C",
        str(repo_root),
        "diff",
        "--name-only",
        "--diff-filter=ACMRT",
        *rev_args,
    ]
    try:
        out = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(
            f"Warning: git diff failed ({e!r}); validating all templates semantically.",
            file=sys.stderr,
        )
        return None
    return [line.strip() for line in out.stdout.splitlines() if line.strip()]


def filter_repo_json_paths(
    repo_root: Path, relative_paths: list[str]
) -> list[Path]:
    out: list[Path] = []
    for line in relative_paths:
        candidate = (repo_root / line).resolve()
        try:
            candidate.relative_to(repo_root)
        except ValueError:
            continue
        if not candidate.is_file() or candidate.suffix.lower() != ".json":
            continue
        parts = {n.lower() for n in candidate.parts}
        if parts & SKIP_DIR_PARTS_LOWER:
            continue
        out.append(candidate)
    return sorted(set(out))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate Gamepad Mapping profile JSON templates."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["."],
        help="Files or directories to scan (default: current directory).",
    )
    parser.add_argument(
        "--warnings-as-errors",
        action="store_true",
        help="Treat warnings as failures.",
    )
    parser.add_argument(
        "--check-duplicate-profile-ids",
        action="store_true",
        help="Fail if the same profileId appears in more than one file.",
    )
    parser.add_argument(
        "--incremental-semantic-git",
        nargs="+",
        default=None,
        metavar="REV",
        help=(
            "Limit full semantic validation to JSON files changed in this git diff. "
            "Pass one revision range (e.g. base...head) or two SHAs (before after). "
            "Falls back to validating all files if git is unavailable or the diff fails."
        ),
    )
    args = parser.parse_args()

    revs = args.incremental_semantic_git
    if revs is not None and not (1 <= len(revs) <= 2):
        print(
            "Error: --incremental-semantic-git requires 1 revision (e.g. A...B) "
            "or 2 revisions (before after).",
            file=sys.stderr,
        )
        return 1

    all_files: list[Path] = []
    for raw in args.paths:
        p = Path(raw).resolve()
        if not p.exists():
            print(f"Error: path not found: {p}", file=sys.stderr)
            return 1
        all_files.extend(iter_json_files(p))

    all_files = sorted(set(all_files))
    if not all_files:
        print("No JSON files found.", file=sys.stderr)
        return 1

    all_set = {f.resolve() for f in all_files}
    semantic_targets = list(all_files)
    incremental = False

    if revs:
        if len(revs) == 2 and is_null_git_object(revs[0]):
            print(
                "Note: incremental git range has a null 'before' SHA; "
                "validating all templates semantically.",
                file=sys.stderr,
            )
        else:
            git_start = Path.cwd()
            root = find_git_root(git_start)
            if root is None:
                print(
                    "Warning: not in a git repository; validating all templates semantically.",
                    file=sys.stderr,
                )
            else:
                rev_args = [revs[0]] if len(revs) == 1 else [revs[0], revs[1]]
                changed_rel = git_changed_paths(root, rev_args)
                if changed_rel is not None:
                    candidates = filter_repo_json_paths(root, changed_rel)
                    semantic_targets = sorted(
                        p for p in candidates if p.resolve() in all_set
                    )
                    incremental = True
                    if not semantic_targets:
                        print(
                            "No template JSON changed in git diff; "
                            "skipping semantic validation.",
                            file=sys.stderr,
                        )

    if args.check_duplicate_profile_ids or not incremental:
        files_to_parse = all_files
    else:
        files_to_parse = semantic_targets
        if not files_to_parse:
            print("OK: nothing to parse.", file=sys.stderr)
            return 0

    parsed: dict[Path, dict[str, Any]] = {}
    any_error = False
    for file_path in files_to_parse:
        rel = file_path.as_posix()
        try:
            parsed[file_path] = load_json_file(file_path)
        except ValueError as e:
            print(f"{rel}: ERROR: {e}", file=sys.stderr)
            any_error = True

    seen_profile_ids: dict[str, list[Path]] = {}
    if args.check_duplicate_profile_ids:
        for file_path, data in parsed.items():
            pid = (data.get("profileId") or "").strip()
            if pid:
                seen_profile_ids.setdefault(pid, []).append(file_path)

    for file_path in semantic_targets:
        if file_path not in parsed:
            continue
        rel = file_path.as_posix()
        data = parsed[file_path]
        errs, warns = validate_profile_object(data, rel)
        for e in errs:
            print(f"{rel}: ERROR: {e}", file=sys.stderr)
        for w in warns:
            print(f"{rel}: WARNING: {w}", file=sys.stderr)
        if errs:
            any_error = True
        if warns and args.warnings_as_errors:
            any_error = True

    if args.check_duplicate_profile_ids:
        for pid, paths in sorted(seen_profile_ids.items()):
            if len(paths) > 1:
                locs = ", ".join(p.as_posix() for p in paths)
                print(
                    f"ERROR: duplicate profileId '{pid}' in files: {locs}",
                    file=sys.stderr,
                )
                any_error = True

    if any_error:
        return 1

    if incremental:
        print(
            f"OK: semantic {len(semantic_targets)}/{len(all_files)} file(s); "
            f"parsed {len(parsed)} file(s)"
            + (" (incl. full tree for duplicate/json check)" if args.check_duplicate_profile_ids else "")
            + ".",
        )
    else:
        print(f"OK: {len(all_files)} file(s) validated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
