import os
import json
from pathlib import Path

def generate_index():
    repo_root = Path(__file__).parent.parent
    index = []
    
    # 扫描所有子目录（忽略以 . 开头的隐藏目录）
    for game_dir in repo_root.iterdir():
        if game_dir.is_dir() and not game_dir.name.startswith('.'):
            # 扫描游戏目录下的所有 .json 文件
            for template_file in game_dir.glob("*.json"):
                try:
                    with open(template_file, 'r', encoding='utf-8-sig') as f:
                        data = json.load(f)
                        
                    # 提取元数据，如果缺失则使用文件信息补全
                    template_info = {
                        "id": data.get("profileId", template_file.stem),
                        "displayName": data.get("displayName", template_file.stem),
                        "author": data.get("author", "Community"),
                        "description": f"Template for {game_dir.name}",
                        "catalogFolder": game_dir.name,
                        "fileName": template_file.name,
                        # 这里的 URL 指向原始文件，下载时我们会用 CDN 替换它
                        "downloadUrl": f"https://raw.githubusercontent.com/Maxim00191/GamepadMapping-CommunityProfiles/main/{game_dir.name}/{template_file.name}"
                    }
                    index.append(template_info)
                except Exception as e:
                    print(f"Error parsing {template_file}: {e}")

    # 写入 index.json
    with open(repo_root / "index.json", 'w', encoding='utf-8') as f:
        json.dump(index, f, indent=2, ensure_ascii=False)
    
    print(f"Successfully generated index with {len(index)} templates.")

if __name__ == "__main__":
    generate_index()
