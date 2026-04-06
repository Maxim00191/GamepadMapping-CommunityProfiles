# GamepadMapping · Community profiles

[简体中文](README_zh.md)

This repository hosts **community-authored gamepad mapping templates** for various games. Templates are JSON files that map controller buttons and sticks to keyboard and mouse actions, including advanced behaviors such as combo chords and radial menus. Import them into the companion tool or application that supports this format.

## Repository layout

- One **folder per game**. The folder name usually matches `templateCatalogFolder` in the template (for example, `Roco Kingdom`).
- Each **JSON file** is one mapping profile. A game may ship multiple profiles for different scenarios or authors (e.g. exploration vs. combat, different `profileId` values).

## Template fields

| Field | Description |
|-------|-------------|
| `schemaVersion` | Format version; currently `1`. |
| `profileId` | Unique profile id; include scenario and author when possible, e.g. `explore-maxim0191`. |
| `templateGroupId` | Shared by a set of profiles (same game/author) so the tool can switch between them as a group. |
| `displayName` | Label shown in the UI. |
| `author` | Author handle or id. |
| `targetProcessName` | Target game executable name (no extension) for automatic window matching. |
| `comboLeadButtons` | Controller buttons that act as “lead” keys for combo chords. |
| `keyboardActions` | Catalog of keyboard/mouse actions: each entry has `id`, `keyboardKey` (e.g. `W`, `MouseX`), a description, and optional localized `descriptions`. |
| `mappings` | Gamepad-to-action mappings: `from` (e.g. `X`, `Back + Start`), `trigger` (`Pressed`, `Tap`, `Released`, …), either `keyboardKey` or an `actionId` referencing `keyboardActions`, plus optional long-press, `radialMenu`, `itemCycle`, and other extensions. |

Some profiles may also include `templateCatalogFolder`, `EffectiveTemplateGroupId`, or similar fields to align with on-disk layout or tool internals.

## Automated checks

Pull requests and pushes to `main` or `master` run a **GitHub Actions** workflow (`.github/workflows/validate-templates.yml`). It discovers every template `*.json` under the repository root (excluding tooling paths such as `.github` and `.scripts`).

**Incremental semantic validation:** on each run, only JSON files that appear in the relevant **git diff** get the full rule pass (the same checks as the companion app: required fields, `keyboardActions` / `mappings` / radial menu cross-references, `templateCatalogFolder`, and so on). That keeps CPU time roughly proportional to the size of the change when the catalog grows.

**Still full-tree for safety:** every template file is still **parsed** on each run so broken JSON anywhere in the tree fails the build, and **global `profileId` uniqueness** is enforced across the whole repo (duplicates require touching more than one file, so a per-diff-only semantic pass is not enough by itself).

**Trade-off:** templates that were not changed in the diff are assumed to remain semantically valid since they last passed on `main`. If you need a one-off full scan locally (for example before a large release), omit `--incremental-semantic-git`.

From the repository root, full scan:

```bash
python .scripts/validate_templates.py . --check-duplicate-profile-ids
```

Same as CI on a PR branch (compare to `main`):

```bash
python .scripts/validate_templates.py . --check-duplicate-profile-ids \
  --incremental-semantic-git "$(git merge-base origin/main HEAD)...HEAD"
```

Python 3.10+ is enough; optional dependencies are listed in `requirements.txt` (currently none beyond the standard library).

### Ensuring Template Quality

This repository uses **CI (Continuous Integration)** and **Branch Protection** to ensure all templates merged into `main` meet the required standards.

1. **Automated Validation (CI):** Every Pull Request automatically triggers the `validate` check. If the JSON is malformed or violates business rules, the CI will fail.
2. **Merge Requirements:** Branch protection rules are active. A PR can only be merged once the CI check passes (green ✅) and necessary reviews are completed.
3. **Local Pre-commit Validation (Recommended):** To save time, we recommend validating your changes locally before pushing. You can run the validation script manually or set up a local Git Hook:
   - Run `git config core.hooksPath .githooks` once to enable local hooks.
   - Once enabled, `git commit` will automatically run the validation and block the commit if errors are found, preventing broken code from reaching GitHub.

## Contributing

1. **Fork** the repo and add or edit JSON under the right game folder (or create a new game folder).
2. Keep JSON valid and keep `schemaVersion` consistent with existing templates; confirm downstream tool support before adding new top-level fields.
3. Open a **Pull Request** and briefly note the game name, version or scenario, and how your profile differs from existing ones.
4. Wait for the **Validate profile templates** workflow to pass on the PR, or run the local command in **Automated checks** first.
5. Only submit content you are allowed to share. Community mappings are provided as-is and are **not guaranteed** to match every game build or every controller layout.

## License and Disclaimer

- **Community Contributions**: Mapping profiles are contributed voluntarily by the community. While we use automated validation to ensure technical correctness, we cannot guarantee compatibility with every game build, client version, or controller hardware.
- **Use at Your Own Risk**: Users are encouraged to verify configurations before use. The maintainers and contributors are not responsible for any issues arising from the use of these third-party profiles.
- **Licensing**: Unless otherwise specified, content in this repository is governed by the `LICENSE` file at the root. Any `LICENSE` file within a specific game folder takes precedence for that folder's content.

