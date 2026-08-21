# backend/tests/core/test_skill_drift.py
"""Skills drift guard (one-way): every code reference a skill makes must
resolve in the codebase. Skills state facts about code; when code moves or
dies, this turns the silent lie into a red test.

Extraction domain (三类断言 + 白名单):
  a) backtick tokens containing ".py" -> file must exist under repo root
  b) backtick CamelCase tokens       -> must appear in backend/ipdb sources
  c) UPPER_SNAKE tokens              -> must appear in backend/ipdb sources
  d) everything else (concepts/env vars/shell snippets) -> ALLOWLIST
"""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]          # 仓库根 (.pi/ 在根)
SKILLS = REPO / ".pi" / "skills"
IPDB = REPO / "backend" / "ipdb"

# d) 类台账: skill 合法的非代码引用, 逐条注明理由
ALLOWLIST = frozenset({
    "ApiSource",        # SKILL.md 墓碑有意提及已删基类 (PR #13 决策, spec §1)
    # --- 概念词/占位符 (c) 类: 非代码引用, 永久豁免 ---
    ".py",            # 扩展名提法 (SKILL.md "imports every .py"), 非文件路径
    ".mmdb",          # 扩展名提法 (archetypes 灰区表), 非文件路径
    "Generated",      # feed 时间戳栏位词 (freshness gate), 非代码符号
    "REJECT",         # discover rubric 判定词, 非代码符号
    "Fields",         # discover dossier 槽位词, 非代码符号
    "Cadence",        # discover dossier 槽位词, 非代码符号
    "backend/ipdb/_sources/<name>.py",  # Phase 3 "创建你的源文件" 占位符, 读取时天然不存在
})

_BT = re.compile(r"`([^`\n]+)`")                    # 反引号标记
_IS_FILE = lambda t: ".py" in t or t.endswith((".env", ".lmdb", ".mmdb"))
_IS_CAMEL = re.compile(r"^_?[A-Z][A-Za-z0-9]*$")
_IS_SNAKE = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")


def _ipdb_blob() -> str:
    parts = [p.read_text(encoding="utf-8", errors="replace")
             for p in IPDB.rglob("*.py")]
    return "\n".join(parts)


def _skill_tokens():
    for md in sorted(SKILLS.rglob("*.md")):
        for tok in _BT.findall(md.read_text(encoding="utf-8")):
            yield md, tok.strip()


def test_guard_infrastructure_finds_references():
    """守卫自身健全性: 提取器必须抓到已知存在的引用(否则守卫空转)."""
    toks = {t for _, t in _skill_tokens()}
    assert any(".py" in t for t in toks), "no .py references found — extractor broken"
    assert any(_IS_CAMEL.match(t) for t in toks), "no CamelCase refs — extractor broken"


def test_skill_code_references_resolve():
    blob = _ipdb_blob()
    problems = []
    for md, tok in _skill_tokens():
        if tok in ALLOWLIST or " " in tok or "/" in tok and ".py" not in tok:
            continue                                   # 白名单/自然语言/shell 片段
        if _IS_FILE(tok):
            # 三类候选: 根相对路径 / backend/ipdb 直下或 ipdb 相对路径 / _sources 裸文件名
            # (triage (b): _source_base.py、_sources/_base.py 等真实文件曾因缺第二候选误报)
            cands = [tok] if tok.startswith("backend/") else \
                [f"backend/ipdb/{tok}", f"backend/ipdb/_sources/{tok}", tok]
            if not any((REPO / c).exists() for c in cands):
                problems.append(f"{md.relative_to(REPO)}: file not found: {tok}")
        elif _IS_CAMEL.match(tok) or _IS_SNAKE.match(tok):
            if tok not in blob:
                problems.append(f"{md.relative_to(REPO)}: symbol not in backend/ipdb: {tok}")
    assert not problems, "\n".join(problems)
