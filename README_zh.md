# GamepadMapping · 社区映射模板

[English](README.md)

本仓库收集玩家为各类游戏编写的手柄按键映射模板。模板以 JSON 格式描述，支持将手柄按键、摇杆与键盘/鼠标操作对应，并支持组合键、轮盘菜单等高级行为。

配套应用会自动通过系统生成的索引发现这些模板，并利用全球 CDN 提供快速、稳定的下载体验。

## 目录结构

> [!TIP]
> **本地提前校验 (推荐)**：为了节省你的开发时间，建议在提交前配置本地 Git Hook：
> 执行 `git config core.hooksPath .githooks` 开启本地钩子。
> 开启后，每次执行 `git commit` 时都会自动运行校验，若不通过则无法提交，从而避免将错误推送到远程。

- 按**游戏**分文件夹：文件夹名通常与模板内的 `templateCatalogFolder` 一致（例如 `Roco Kingdom`）。
- 每个 **JSON 文件**对应一套映射配置：同一游戏下可有多种场景或作者变体（如探索 / 战斗、不同 `profileId`）。
- **`index.json` (自动管理)**：全库模板的索引文件。**请勿手动修改此文件**，它由 GitHub Actions 自动更新。

## 自动化系统

本仓库采用零维护贡献设计：

1.  **自动索引**：GitHub Action (`update-index.yml`) 会在每次推送到 `main` 分支时运行。它会自动扫描仓库，并从 JSON 文件中提取元数据（显示名称、作者等）来重新生成 `index.json`。
2.  **CDN 分发**：应用通过 **jsDelivr CDN** 获取索引和模板，确保全球范围内（包括访问 GitHub 受限的地区）的高可用性和极速下载。
3.  **自动校验**：每个 Pull Request 都会经过自动化校验，确保 JSON 语法正确且符合业务逻辑（引用完整、ID 唯一等）。

## 如何贡献

欢迎提交你的映射配置！添加新模板的步骤如下：

1.  **Fork** 本仓库。
2.  为游戏创建一个文件夹（如果尚不存在）。
3.  将你的映射 JSON 文件放入该文件夹。
    *   请确保 JSON 内部设置了 `displayName` 和 `author` 字段。
    *   文件名建议具有描述性（如 `explore-maxim0191.json`）。
4.  提交 **Pull Request**。
5.  PR 合并后，系统会自动更新索引，你的模板将立即出现在应用的社区目录中。

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

## 许可与免责声明

- **社区贡献**：本仓库中的映射文件由社区成员自愿提交。虽然我们通过自动化校验尽力确保格式正确，但无法保证其与所有游戏版本、客户端或特定手柄型号的完全兼容性。
- **使用风险**：请在导入前自行核对配置内容。因使用第三方映射配置而产生的任何问题，需由使用者自行承担。
- **开源许可**：除非另有说明，本仓库内容遵循根目录下的 `LICENSE` 文件。
