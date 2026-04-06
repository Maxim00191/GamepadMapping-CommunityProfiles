# GamepadMapping · 社区映射模板

[English](README.md)

本仓库收集玩家为各类游戏编写的手柄按键映射模板，供配套工具（或应用）导入使用。模板以 JSON 描述：将手柄按键、摇杆与键盘/鼠标操作对应，并支持组合键、轮盘菜单等高级行为。

## 目录结构

- 按**游戏**分文件夹，文件夹名通常与模板内的 `templateCatalogFolder` 一致（例如 `Roco Kingdom`）。
- 每个 JSON 文件对应一套**映射配置**（一个 profile），同一游戏下可有多种场景或作者变体（如探索 / 战斗、不同 `profileId`）。

## 模板文件约定

| 字段 | 说明 |
|------|------|
| `schemaVersion` | 模板格式版本，当前为 `1`。 |
| `profileId` | 配置唯一标识，建议包含场景与作者信息，如 `explore-maxim0191`。 |
| `templateGroupId` | 同一作者/同一游戏的一组模板共用，用于在工具内成组切换。 |
| `displayName` | 在界面中显示的名称。 |
| `author` | 作者昵称或 ID。 |
| `targetProcessName` | 目标游戏进程名（无扩展名），用于自动匹配窗口。 |
| `comboLeadButtons` | 作为组合键“先导键”的手柄按键列表。 |
| `keyboardActions` | 键盘/鼠标动作目录：每项含 `id`、`keyboardKey`（如 `W`、`MouseX`）、说明及可选多语言 `descriptions`。 |
| `mappings` | 手柄到动作的映射：含 `from`（如按钮 `X`、`Back + Start`）、`trigger`（如 `Pressed`、`Tap`、`Released`）、`keyboardKey` 或引用 `keyboardActions` 的 `actionId`，以及长按、轮盘菜单（`radialMenu`）、物品循环（`itemCycle`）等扩展字段。 |

部分模板可能包含 `templateCatalogFolder`、`EffectiveTemplateGroupId` 等字段，以与目录或工具内部逻辑对齐。

## 自动化校验

针对 **Pull Request** 以及推送到 **`main` / `master`** 的提交，仓库会通过 **GitHub Actions**（`.github/workflows/validate-templates.yml`）自动校验：在仓库根目录下发现所有模板 `*.json`（会跳过 `.github`、`.scripts` 等工具目录）。

**增量语义校验：** 每次运行只对 **git diff 里出现过的** JSON 做完整的规则检查（与配套应用一致：必填字段、`keyboardActions` / `mappings` / 轮盘引用、`templateCatalogFolder` 等）。模板数量变大后，耗时可大致随「本次改动涉及的模板数」增长，而不是随全库文件数线性放大。

**仍保留全树必要步骤：** 每个模板文件仍会被 **解析**，任意位置的 JSON 语法错误都会让检查失败；**全仓库 `profileId` 去重** 也会扫描整棵树（重复往往涉及多个文件，仅靠 diff 无法保证安全）。

**取舍：** 未出现在本次 diff 里的模板，默认视为仍满足语义规则（与它们在 `main` 上最近一次通过时一致）。若需要一次性全量语义扫描（例如大版本发布前），本地运行时不要加 `--incremental-semantic-git`。

在仓库根目录，全量语义扫描：

```bash
python .scripts/validate_templates.py . --check-duplicate-profile-ids
```

与 CI 类似，仅对相对 `main` 的改动做语义校验：

```bash
python .scripts/validate_templates.py . --check-duplicate-profile-ids \
  --incremental-semantic-git "$(git merge-base origin/main HEAD)...HEAD"
```

需 **Python 3.10+**；第三方依赖见根目录 `requirements.txt`（当前仅标准库即可运行）。

### 如何确保模板质量？

本仓库通过 **CI (持续集成)** 和 **分支保护** 来确保所有合并到 `main` 分支的模板都符合规范。

1. **自动化校验 (CI)：** 所有的 Pull Request 都会自动触发 `validate` 检查。如果 JSON 格式错误或不符合业务规则，CI 将会报错。
2. **合并要求：** 仓库已开启分支保护规则，只有当 CI 检查通过（显示绿色 ✅）且通过必要的代码审核后，PR 才能被合并。
3. **本地提前校验 (推荐)：** 为了节省你的开发时间，建议在提交前进行本地校验。你可以手动运行校验脚本，或者配置本地 Git Hook：
   - 执行 `git config core.hooksPath .githooks` 开启本地钩子。
   - 开启后，每次执行 `git commit` 时都会自动运行校验，若不通过则无法提交，从而避免将错误推送到远程。

## 如何贡献

1. **Fork** 本仓库，在对应游戏文件夹下新增或修改 JSON（或新建游戏文件夹）。
2. 保持 JSON 有效且 `schemaVersion` 与现有模板一致；新增字段前请确认下游工具是否支持。
3. 提交 **Pull Request**，在说明中简要写清：游戏名、适用版本或场景、与已有模板的区别。
4. 等待 PR 上的 **Validate profile templates** 工作流通过；也可在提交前按上文「自动化校验」在本地先跑一遍。
5. 请确保你有权分享该配置内容；映射方案为社区贡献，**不保证**与所有游戏版本或所有手柄布局兼容。

## 许可与免责声明

- **社区贡献**：本仓库中的映射文件由社区成员自愿提交。虽然我们通过 CI 尽力确保格式正确，但无法保证其与所有游戏版本、客户端或特定手柄型号的完全兼容性。
- **使用风险**：请在导入前自行核对配置内容。因使用第三方映射配置而产生的任何问题，需由使用者自行承担。
- **开源许可**：除非另有说明，本仓库内容遵循根目录下的 `LICENSE` 文件。若某文件夹内另附许可说明，则该说明具有更高优先级。

