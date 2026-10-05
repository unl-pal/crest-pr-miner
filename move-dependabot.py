import json
import os

from pathlib import Path

data_dir = Path('data')

for file_path in list(data_dir.rglob("[0-9]*.json")):
    if '/reviews/' in str(file_path) or '/commits/' in str(file_path):
        continue

    with open(file_path, 'r') as f:
        data = json.load(f)
    if data['user']['login'] == 'dependabot[bot]' or data['user']['login'] == 'dependabot-preview[bot]':
        dir_path = file_path.parent
        target_path = Path('skipped/' + '/'.join(str(dir_path).split('/')[1:]))
        target_path.mkdir(parents=True, exist_ok=True)

        print(file_path, dir_path, target_path)
        os.rename(dir_path, target_path)

        dir_path = dir_path.parent
        if not sum(1 for item in dir_path.iterdir()):
            dir_path.rmdir()

            dir_path = dir_path.parent
            if not sum(1 for item in dir_path.iterdir()):
                dir_path.rmdir()
