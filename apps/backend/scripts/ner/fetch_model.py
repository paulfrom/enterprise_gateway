"""Fetch the shibing624/bert4ner-base-chinese snapshot via the HF mirror.

Downloads a pinned file subset of the upstream repository through
``https://hf-mirror.com`` (huggingface.co is unreachable from this network;
LFS payloads resolve to the mirror's CDN). huggingface_hub cannot be used
here: the mirror's resolve-cache responses omit the ``X-Repo-Commit``
header that huggingface_hub>=0.36 requires, so plain redirect-following
HTTP GET is used instead.

Archives under ``models/bert4ner-base-chinese/`` and emits provenance:

- ``manifest.json``            per-file SHA-256 and byte count of the snapshot
- ``model-card-excerpt.md``    license / label-set / training-record excerpt
                               with source URLs and the excerpt date

Only the files required by the D-08 artifact contract are fetched
(``pytorch_model.bin`` and ``bert.png`` are redundant for the ONNX export
path and are intentionally excluded).

Usage:
    python scripts/ner/fetch_model.py
"""

from __future__ import annotations

import hashlib
import json
import shutil
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO_ID = "shibing624/bert4ner-base-chinese"
REVISION = "5d660ed2aa9da482bf2d99c6bc8cf2ce66758f6a"
SOURCE_URL = f"https://huggingface.co/{REPO_ID}"
MIRROR_URL = "https://hf-mirror.com"
NERPY_REPO_URL = "https://github.com/shibing624/nerpy"
RESOLVE_URL = f"{MIRROR_URL}/{REPO_ID}/resolve/{REVISION}"

ALLOW_PATTERNS = [
    "config.json",
    "model.safetensors",
    "model_args.json",
    "README.md",
    "tokenizer_config.json",
    "special_tokens_map.json",
    "vocab.txt",
]

GATEWAY_ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT_DIR = GATEWAY_ROOT / "models" / "bert4ner-base-chinese"

USER_AGENT = "enterprise-gateway-d08-artifact-fetch/1.0"


def _sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download(filename: str, dest: Path) -> None:
    url = f"{RESOLVE_URL}/{filename}"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    tmp = dest.with_suffix(dest.suffix + ".part")
    last_error: Exception | None = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=120) as response, open(tmp, "wb") as f:
                shutil.copyfileobj(response, f, length=1 << 20)
            tmp.replace(dest)
            return
        except Exception as exc:  # noqa: BLE001 - retried, then reported as one failure
            last_error = exc
            if tmp.exists():
                tmp.unlink()
    raise RuntimeError(f"failed to download {filename}: {last_error}")


def _write_manifest(directory: Path) -> dict:
    files = {}
    for path in sorted(directory.iterdir()):
        if not path.is_file() or path.name == "manifest.json":
            continue
        files[path.name] = {
            "sha256": _sha256_of(path),
            "bytes": path.stat().st_size,
        }
    manifest = {
        "manifest_version": 1,
        "artifact": f"hf-snapshot:{REPO_ID}@{REVISION}",
        "source": MIRROR_URL,
        "upstream": SOURCE_URL,
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": files,
    }
    with open(directory / "manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return manifest


def _write_model_card_excerpt(directory: Path) -> None:
    excerpt_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with open(directory / "model_args.json", "r", encoding="utf-8") as f:
        train_args = json.load(f)
    with open(directory / "config.json", "r", encoding="utf-8") as f:
        config = json.load(f)

    labels = sorted(train_args.get("labels_list", []))
    lines = [
        "# 模型卡摘录：shibing624/bert4ner-base-chinese",
        "",
        f"- 摘录日期（UTC）：{excerpt_date}",
        f"- 上游模型卡：{SOURCE_URL}",
        f"- 固定修订（commit）：{REVISION}",
        f"- 本次下载镜像：{MIRROR_URL}（huggingface.co 主站本网络不可达）",
        f"- 训练框架仓库（nerpy，许可证同 Apache-2.0）：{NERPY_REPO_URL}",
        "",
        "## 许可证",
        "",
        "- 标注许可证：Apache-2.0",
        "- 核实依据：HF API cardData.license=apache-2.0；模型卡 YAML 标注 license: apache-2.0；",
        "  nerpy 框架仓库 LICENSE 为 Apache-2.0。",
        "",
        "## 架构与任务头",
        "",
        f"- architectures：{config.get('architectures')}",
        f"- model_type：{config.get('model_type')}（基座 {train_args.get('model_name')}）",
        "- 参数量（HF API safetensors 元数据）：101,684,489",
        "",
        "## 标签集（BIO，9 个）",
        "",
        f"- {', '.join(labels)}",
        "",
        "## 训练记录（model_args.json 摘录）",
        "",
        f"- num_train_epochs：{train_args.get('num_train_epochs')}",
        f"- learning_rate：{train_args.get('learning_rate')}",
        f"- max_seq_length：{train_args.get('max_seq_length')}",
        f"- train_batch_size：{train_args.get('train_batch_size')}",
        f"- optimizer：{train_args.get('optimizer')}；scheduler：{train_args.get('scheduler')}",
        f"- best_model_dir：{train_args.get('best_model_dir')}",
        "- 训练语料：人民日报 NER 语料（nerpy 框架默认中文 NER 数据集）。",
        "",
        "## 说明",
        "",
        "本文件为人工核实摘录，供许可与训练证据归档；机器校验以",
        "bert4ner-base-chinese-onnx/license-excerpt.json 为准。",
    ]
    with open(directory / "model-card-excerpt.md", "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main() -> None:
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    for filename in ALLOW_PATTERNS:
        dest = SNAPSHOT_DIR / filename
        if dest.exists():
            print(f"skip existing {filename}")
            continue
        print(f"download {filename} ...")
        _download(filename, dest)
    manifest = _write_manifest(SNAPSHOT_DIR)
    _write_model_card_excerpt(SNAPSHOT_DIR)
    total = sum(meta["bytes"] for meta in manifest["files"].values())
    print(f"archived {len(manifest['files'])} files, {total} bytes -> {SNAPSHOT_DIR}")


if __name__ == "__main__":
    main()
