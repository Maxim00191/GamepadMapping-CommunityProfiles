import os
import json
from pathlib import Path

SKIP_DIR_PARTS_LOWER = frozenset(
    {
        "node_modules",
        ".git",
        ".github",
        ".scripts",
        "__pycache__",
        ".venv",
        "venv",
        "cloudflare",
        ".wrangler",
    }
)


def should_skip_path(path: Path, repo_root: Path) -> bool:
    try:
        rel = path.resolve().relative_to(repo_root.resolve())
    except ValueError:
        return True
    if path.name.lower() == "index.json":
        return True
    parts_lower = {p.lower() for p in rel.parts}
    return bool(parts_lower & SKIP_DIR_PARTS_LOWER)


def repo_owner_name() -> tuple[str, str]:
    gh = (os.environ.get("GITHUB_REPOSITORY") or "").strip()
    if gh and "/" in gh:
        o, _, n = gh.partition("/")
        return o, n
    raw = (os.environ.get("COMMUNITY_INDEX_GITHUB_REPO") or "").strip()
    if raw and "/" in raw:
        o, _, n = raw.partition("/")
        return o, n
    return "Maxim00191", "GamepadMapping-CommunityProfiles"


def branch_name() -> str:
    b = (os.environ.get("COMMUNITY_INDEX_GITHUB_BRANCH") or "").strip()
    return b if b else "main"


def generate_index():
    repo_root = Path(__file__).parent.parent.resolve()
    owner, repo = repo_owner_name()
    branch = branch_name()
    index = []

    for template_file in sorted(repo_root.rglob("*.json")):
        if should_skip_path(template_file, repo_root):
            continue
        try:
            with open(template_file, "r", encoding="utf-8-sig") as f:
                data = json.load(f)

            rel = template_file.relative_to(repo_root)
            rel_posix = rel.as_posix()
            parent = rel.parent
            catalog = "" if parent == Path(".") else parent.as_posix()

            desc = (data.get("communityListingDescription") or "").strip()
            if not desc and catalog:
                top = rel.parts[0]
                desc = f"Template for {top}"
            elif not desc:
                desc = "Community template"

            template_info = {
                "id": data.get("profileId", template_file.stem),
                "displayName": data.get("displayName", template_file.stem),
                "author": data.get("author", "Community"),
                "description": desc,
                "catalogFolder": catalog,
                "fileName": template_file.name,
                "downloadUrl": f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{rel_posix}",
            }
            index.append(template_info)
        except Exception as e:
            print(f"Error parsing {template_file}: {e}")

    with open(repo_root / "index.json", "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2, ensure_ascii=False)

    print(f"Successfully generated index with {len(index)} templates.")


if __name__ == "__main__":
    generate_index()
