# GamepadMapping · Community profiles

[简体中文](README_zh.md)

This repository hosts **community-authored gamepad mapping templates** for various games. Templates are JSON files that map controller buttons and sticks to keyboard and mouse actions, including advanced behaviors such as combo chords and radial menus.

The main application automatically discovers these templates via a system-generated index and provides fast, reliable downloads through a global CDN.

## Repository layout

> [!TIP]
> **Local Pre-commit Validation (Recommended)**: To save time, we recommend setting up a local Git Hook before pushing:
> Run `git config core.hooksPath .githooks` once to enable local hooks.
> Once enabled, `git commit` will automatically run the validation and block the commit if errors are found, preventing broken code from reaching GitHub.

- One **folder per game**. The folder name usually matches `templateCatalogFolder` in the template (for example, `Roco Kingdom`).
- Each **JSON file** is one mapping profile. A game may ship multiple profiles for different scenarios or authors (e.g. exploration vs. combat, different `profileId` values).
- **`index.json` (Automated)**: A system-managed index of all available templates. **Do not modify this file manually**; it is automatically updated by GitHub Actions.

## Automated system

This repository is designed for zero-maintenance contribution:

1.  **Automatic Indexing**: A GitHub Action (`update-index.yml`) runs on every push to `main`. It scans the repository and regenerates `index.json` with the latest metadata (display names, authors, etc.) extracted directly from the JSON files.
2.  **CDN Distribution**: The application fetches the index and templates via the **jsDelivr CDN**, ensuring high availability and fast download speeds worldwide, including in regions with restricted access to GitHub.
3.  **Validation**: Every Pull Request is automatically validated for JSON syntax and semantic correctness (cross-references, unique IDs, etc.).

## Contributing

We welcome contributions! To add a new template:

1.  **Fork** the repo.
2.  Create a folder for the game (if it doesn't exist).
3.  Add your mapping JSON file into that folder.
    *   Ensure `displayName` and `author` fields are set inside the JSON.
    *   The filename should ideally be descriptive (e.g., `explore-maxim0191.json`).
4.  Open a **Pull Request**.
5.  Once merged, the system will automatically update the index, and your template will appear in the application's community catalog.

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

## License and Disclaimer

- **Community Contributions**: Mapping profiles are contributed voluntarily by the community. While we use automated validation to ensure technical correctness, we cannot guarantee compatibility with every game build, client version, or controller hardware.
- **Use at Your Own Risk**: Users are encouraged to verify configurations before use. The maintainers and contributors are not responsible for any issues arising from the use of these third-party profiles.
- **Licensing**: Unless otherwise specified, content in this repository is governed by the `LICENSE` file at the root.
