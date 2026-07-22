# Reserved-IP Short-Circuit + Expand-Disagreements Toggle — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop private/reserved (bogon) IPs from surfacing false-positive "malicious" verdicts by short-circuiting `lookup()` and marking them "保留地址"; and make the "Expand disagreements" button a toggle.

**Architecture:** Single backend chokepoint — `lookup()` detects bogon IPs via a new pure `is_reserved()` helper and returns a reserved `LookupResult` without querying any source. The `is_reserved` flag flows through `to_dict()` → JSON → frontend, where `threatSummary` maps it to a `"reserved"` verdict rendered as a gray "保留地址" badge. CSV/SummaryBar derive from `threatSummary`, so they follow automatically (SummaryBar needs a small exclusion). All four endpoints are covered because they all call `lookup()`.

**Tech Stack:** Python 3.12 / FastAPI / stdlib `ipaddress` (backend, pytest); React 19 / TypeScript / vitest + @testing-library/react (frontend).

## Global Constraints

- **Bogon gate (verbatim):** `return (not addr.is_global) or addr.is_multicast` — covers RFC1918, loopback, link-local, CGNAT, documentation, benchmarking, `0.0.0.0/8`, `240.0.0.0/4`, broadcast, plus multicast `224.0.0.0/4`. Do NOT use `is_private` (returns False for CGNAT `100.64.0.0/10`).
- **Single label "保留地址"** — no sub-type classification (YAGNI).
- **New field:** `LookupResult.is_reserved: bool = False`, serialized in `to_dict()`.
- **Short-circuit location:** in `lookup()`, AFTER the db-loaded guard and IPv4 format check, BEFORE the source loop. Order in `lookup()`: db guard → format check → `is_reserved` short-circuit → source loop.
- **STIX endpoint:** reserved IP returns HTTP 400 `"reserved address: no threat intel"`.
- **Backend tests:** `cd backend && .venv/bin/python -m pytest <file> -v`. New backend test files must pass.
- **Frontend tests:** `cd frontend && npx vitest run <path>` (jsdom, RTL). Build: `cd frontend && npm run build`. Lint: `cd frontend && npm run lint`.
- **Lint baseline:** the repo has **9 pre-existing lint errors** not introduced by this work. New/modified files must add **zero** new lint errors. Verification = new files clean + total errors still ≤ 9.
- **Gitignore:** `docs/superpowers/` is gitignored. The plan file itself is committed with `git add -f`. Code/test files are tracked normally (plain `git add`).
- **Shared file:** Tasks 5, 6, 7 all modify `frontend/src/components/ResultTable.tsx` — they MUST run sequentially (subagent-driven handles this).

---

## Task 1: Backend foundation — `is_reserved()` + `LookupResult.is_reserved` field

**Files:**
- Create: `backend/ipdb/_reserved.py`
- Modify: `backend/ipdb/_types.py` (`LookupResult` dataclass ~line 101, `to_dict()` ~line 113)
- Test: `backend/test_reserved.py` (create)

**Interfaces:**
- Produces: `is_reserved(ip: str) -> bool` (module `ipdb._reserved`); `LookupResult.is_reserved: bool` field (default `False`), serialized as `"is_reserved"` key by `to_dict()`.

- [ ] **Step 1: Write the failing tests**

Create `backend/test_reserved.py`:

```python
"""is_reserved() identifies non-globally-routable (bogon) IPs (RFC 6890),
and LookupResult.is_reserved serializes through to_dict()."""
from ipdb._reserved import is_reserved
from ipdb._types import LookupResult, MergedField


def test_rfc1919_private_ranges_are_reserved():
    assert is_reserved("10.0.0.1")
    assert is_reserved("172.16.0.1")
    assert is_reserved("192.168.1.1")


def test_loopback_is_reserved():
    assert is_reserved("127.0.0.1")
    assert is_reserved("127.255.255.254")


def test_link_local_is_reserved():
    assert is_reserved("169.254.1.1")


def test_cgnat_is_reserved_catches_is_private_gap():
    # CGNAT 100.64.0.0/10: Python's is_private returns False here — is_global catches it.
    assert is_reserved("100.64.0.1")
    assert is_reserved("100.127.255.254")


def test_multicast_is_reserved():
    assert is_reserved("224.0.0.1")


def test_reserved_and_unspecified_are_reserved():
    assert is_reserved("240.0.0.1")
    assert is_reserved("0.0.0.0")


def test_public_ips_are_not_reserved():
    assert not is_reserved("8.8.8.8")
    assert not is_reserved("1.1.1.1")


def test_invalid_format_is_not_reserved():
    # Format validation is lookup()'s job; is_reserved returns False rather than raising.
    assert not is_reserved("not-an-ip")


def _make(ip="8.8.8.8", is_reserved_flag=False):
    return LookupResult(
        ip=ip,
        country=MergedField("US", 0, "voting", []),
        asn=MergedField(0, 0, "voting", []),
        as_name=MergedField("X", 0, "voting", []),
        ip_range=MergedField("1.0.0.0/24", 0, "voting", []),
        is_isp=False,
        classifications={},
        is_reserved=is_reserved_flag,
    )


def test_lookupresult_is_reserved_defaults_false():
    r = _make()
    assert r.is_reserved is False
    assert r.to_dict()["is_reserved"] is False


def test_lookupresult_is_reserved_true_serializes():
    r = _make(ip="10.0.0.1", is_reserved_flag=True)
    assert r.is_reserved is True
    assert r.to_dict()["is_reserved"] is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && .venv/bin/python -m pytest test_reserved.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ipdb._reserved'` (and `LookupResult` has no `is_reserved`).

- [ ] **Step 3: Create `is_reserved()` module**

Create `backend/ipdb/_reserved.py`:

```python
"""Identify non-globally-routable (bogon) IPv4 addresses (IANA RFC 6890).

A reserved address cannot appear as a source on the public internet, so it has
no meaningful public threat intelligence. lookup() short-circuits these so they
are never queried against threat/geo sources (avoiding false-positive malicious
verdicts from feeds that happen to contain private ranges) and never sent to
online enrichers (saving quota).

Gate: `not addr.is_global or addr.is_multicast`.
- is_global is computed by stdlib ipaddress directly from the IANA IPv4
  Special-Purpose Address Registry; it covers RFC1918 private, loopback,
  link-local, CGNAT (100.64.0.0/10), documentation, benchmarking, 0.0.0.0/8,
  240.0.0.0/4 reserved, and limited broadcast.
- is_private is NOT used: it returns False for CGNAT (the one range where
  is_private and is_global are both False).
- multicast (224.0.0.0/4) is added explicitly: it is a group-address range,
  not in the "globally reachable" column, and feeds listing it are noise.

NOTE for future Plan 3 (online enrichers): when _enrich_results is wired up,
it MUST skip IPs whose LookupResult.is_reserved is True.
"""
import ipaddress


def is_reserved(ip: str) -> bool:
    """True if ip is a non-globally-routable (bogon) IPv4 address."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return False
    return (not addr.is_global) or addr.is_multicast
```

- [ ] **Step 4: Add `is_reserved` field to `LookupResult` and serialize it**

In `backend/ipdb/_types.py`, the `LookupResult` dataclass currently ends with:

```python
    attributes: dict = field(default_factory=dict)   # dict[str, list[AssetStatement]] — pure陈述
    error: str | None = None
```

Change it to add the field after `error`:

```python
    attributes: dict = field(default_factory=dict)   # dict[str, list[AssetStatement]] — pure陈述
    error: str | None = None
    is_reserved: bool = False
```

In `LookupResult.to_dict()` (the `return {...}` dict), add the key. Find this line near the end of `to_dict()`:

```python
            **({"error": self.error} if self.error else {}),
        }
```

Change to:

```python
            **({"error": self.error} if self.error else {}),
            "is_reserved": self.is_reserved,
        }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && .venv/bin/python -m pytest test_reserved.py -v`
Expected: PASS (11 tests).

- [ ] **Step 6: Commit**

```bash
git add backend/ipdb/_reserved.py backend/ipdb/_types.py backend/test_reserved.py
git commit -m "feat(backend): add is_reserved() bogon check + LookupResult.is_reserved"
```

---

## Task 2: Backend — short-circuit `lookup()` for reserved IPs

**Files:**
- Modify: `backend/ipdb/_registry.py` (imports ~line 18; `lookup()` ~line 322; add `_reserved_result` after `_error_result` ~line 411)
- Test: `backend/test_lookup_reserved.py` (create)

**Interfaces:**
- Consumes: `is_reserved(ip)` from `ipdb._reserved` (Task 1); `LookupResult.is_reserved` field (Task 1).
- Produces: `lookup()` returns a `LookupResult` with `is_reserved=True`, empty `classifications`, `error=None` for bogon IPs, WITHOUT calling any source's `query()`.

- [ ] **Step 1: Write the failing tests**

Create `backend/test_lookup_reserved.py`:

```python
"""lookup() short-circuits reserved IPs: no source is queried, result is marked."""
import ipdb._registry as reg
from ipdb._types import SourceHealth


class _ProbeSource:
    """A source whose query() must never be reached for a reserved IP."""
    name = "probe"
    fields = ("is_malicious",)
    reliability = 0.5
    authoritative_for = []

    def query(self, ip):
        raise AssertionError(
            f"source.query must not be called for reserved IP {ip}")

    def health(self):
        return SourceHealth(name="probe", loaded=True, record_count=1,
                            last_updated=None, is_stale=False)


def test_lookup_reserved_returns_is_reserved_without_querying(monkeypatch):
    monkeypatch.setattr(reg, "_sources", [_ProbeSource()])
    result = reg.lookup("10.0.0.1")
    assert result.is_reserved is True
    assert result.classifications == {}
    assert result.error is None


def test_lookup_reserved_serializes_flag(monkeypatch):
    monkeypatch.setattr(reg, "_sources", [_ProbeSource()])
    assert reg.lookup("192.168.1.1").to_dict()["is_reserved"] is True


def test_lookup_public_ip_still_queries_source(monkeypatch):
    """Regression guard: a public IP must still reach the source loop."""
    called = {"n": 0}

    class _CountingSource(_ProbeSource):
        def query(self, ip):
            called["n"] += 1
            return {}

    monkeypatch.setattr(reg, "_sources", [_CountingSource()])
    reg.lookup("8.8.8.8")
    assert called["n"] == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && .venv/bin/python -m pytest test_lookup_reserved.py -v`
Expected: FAIL — `result.is_reserved` is `False` (no short-circuit yet; the probe's `query()` raises `AssertionError`).

- [ ] **Step 3: Wire the short-circuit into `lookup()`**

In `backend/ipdb/_registry.py`, add the import. Find this existing import line (~line 18):

```python
from ._evidence import route_record, SCALAR_SLOTS, ASSET_SLOTS
```

Add immediately after it:

```python
from ._evidence import route_record, SCALAR_SLOTS, ASSET_SLOTS
from ._reserved import is_reserved
```

In `lookup()`, find the format-validation block:

```python
    try:
        ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return _error_result(ip)
```

Add the short-circuit immediately after it (before the `# Collect scalar fields...` comment):

```python
    try:
        ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return _error_result(ip)
    if is_reserved(ip):
        return _reserved_result(ip)
```

Add the `_reserved_result` helper. Find the existing `_error_result` function:

```python
def _error_result(ip: str) -> LookupResult:
    return LookupResult(
        ip=ip,
        country=MergedField("N/A", 0, "voting", []),
        asn=MergedField(0, 0, "voting", []),
        as_name=MergedField("N/A", 0, "voting", []),
        ip_range=MergedField("N/A", 0, "voting", []),
        is_isp=False,
        classifications={},
        attributes={},
        error="invalid IP format",
    )
```

Add `_reserved_result` immediately after `_error_result` (mirrors it, but `is_reserved=True` and no `error`):

```python
def _reserved_result(ip: str) -> LookupResult:
    return LookupResult(
        ip=ip,
        country=MergedField("N/A", 0, "voting", []),
        asn=MergedField(0, 0, "voting", []),
        as_name=MergedField("N/A", 0, "voting", []),
        ip_range=MergedField("N/A", 0, "voting", []),
        is_isp=False,
        classifications={},
        attributes={},
        is_reserved=True,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && .venv/bin/python -m pytest test_lookup_reserved.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Run the full backend suite to confirm no regressions**

Run: `cd backend && .venv/bin/python -m pytest -q`
Expected: PASS (all pre-existing tests still green; the new reserved behavior does not change public-IP results).

- [ ] **Step 6: Commit**

```bash
git add backend/ipdb/_registry.py backend/test_lookup_reserved.py
git commit -m "feat(backend): short-circuit lookup() for reserved IPs"
```

---

## Task 3: Backend — STIX endpoint rejects reserved IPs with 400

**Files:**
- Modify: `backend/main.py` (`lookup_stix` ~line 255)
- Test: `backend/test_main_routes.py` (add a method to `TestLookupResponseShape`)

**Interfaces:**
- Consumes: `result.is_reserved` from `lookup()` (Task 2).
- Produces: `GET /api/lookup/{ip}/stix` returns HTTP 400 with detail `"reserved address: no threat intel"` for bogon IPs.

- [ ] **Step 1: Write the failing test**

In `backend/test_main_routes.py`, inside `class TestLookupResponseShape` (which already sets up `cls.client = TestClient(main.app)` with `load_db()` in `setup_class`), add this method after `test_invalid_ip_has_error`:

```python
    def test_stix_reserved_ip_returns_400(self):
        resp = self.client.get("/api/lookup/10.0.0.1/stix")
        assert resp.status_code == 400
        assert "reserved" in resp.json()["detail"].lower()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd backend && .venv/bin/python -m pytest test_main_routes.py::TestLookupResponseShape::test_stix_reserved_ip_returns_400 -v`
Expected: FAIL — without the guard, a reserved IP has no `error`, so the endpoint calls `to_stix_bundle(result)` which returns `None` (stix2 may be uninstalled) → HTTP 501, not 400. (If stix2 IS installed, the bundle builds from empty data and returns 200 — still not 400.) Either way, status != 400.

- [ ] **Step 3: Add the guard to the STIX endpoint**

In `backend/main.py`, find `lookup_stix`:

```python
@app.get("/api/lookup/{ip}/stix")
async def lookup_stix(ip: str):
    """Single IP STIX 2.1 Bundle export."""
    from ipdb._stix_export import to_stix_bundle

    result = lookup(ip)
    if result.error:
        raise HTTPException(400, result.error)

    bundle = to_stix_bundle(result)
```

Add the reserved guard immediately after the `result.error` check:

```python
    result = lookup(ip)
    if result.error:
        raise HTTPException(400, result.error)
    if result.is_reserved:
        raise HTTPException(400, "reserved address: no threat intel")

    bundle = to_stix_bundle(result)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd backend && .venv/bin/python -m pytest test_main_routes.py::TestLookupResponseShape::test_stix_reserved_ip_returns_400 -v`
Expected: PASS.

- [ ] **Step 5: Run the full backend suite**

Run: `cd backend && .venv/bin/python -m pytest -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/main.py backend/test_main_routes.py
git commit -m "fix(backend): STIX endpoint rejects reserved IPs with 400"
```

---

## Task 4: Frontend — model the `"reserved"` verdict

**Files:**
- Modify: `frontend/src/api.ts` (`LookupResult` interface ~line 47)
- Modify: `frontend/src/components/threatDisplay.ts` (`VERDICT_LABEL`/`VERDICT_STYLE`/`VERDICT_RANK` ~lines 15-33; `threatSummary` ~line 69)
- Test: `frontend/src/components/__tests__/threatDisplay.test.ts` (add a test)

**Interfaces:**
- Produces: `LookupResult.is_reserved?: boolean`; `threatSummary(r)` returns `verdict: "reserved"` (with `hasThreats: false`) when `r.is_reserved`; `"reserved"` entries in the verdict label/style/rank maps.

- [ ] **Step 1: Write the failing test**

In `frontend/src/components/__tests__/threatDisplay.test.ts`, add this test inside the existing `describe("threatDisplay", ...)` block (after the "reports clean" test):

```typescript
  it("threatSummary reports reserved when is_reserved", () => {
    const reserved = { ...dirty, is_reserved: true, classifications: {} };
    const s = threatSummary(reserved);
    expect(s.verdict).toBe("reserved");
    expect(s.hasThreats).toBe(false);
  });
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd frontend && npx vitest run src/components/__tests__/threatDisplay.test.ts`
Expected: FAIL — `threatSummary` returns `verdict: "clean"` for the reserved fixture (no classifications), not `"reserved"`. (TypeScript may also complain about `is_reserved` not on the type — that is expected; Step 3 adds it.)

- [ ] **Step 3: Add the `is_reserved` field to the `LookupResult` type**

In `frontend/src/api.ts`, the `LookupResult` interface currently ends with:

```typescript
  attributes?: Record<string, AssetStatement[]>;
  error?: string;
}
```

Change to:

```typescript
  attributes?: Record<string, AssetStatement[]>;
  error?: string;
  is_reserved?: boolean;
}
```

- [ ] **Step 4: Add the `"reserved"` verdict to the maps and `threatSummary`**

In `frontend/src/components/threatDisplay.ts`, add a `reserved` entry to each of the three maps.

`VERDICT_LABEL` (currently):

```typescript
export const VERDICT_LABEL: Record<string, string> = {
  malicious: "恶意",
  suspicious: "可疑",
  benign: "可信",
  informational: "未知",
  clean: "—",
};
```

Add `reserved`:

```typescript
export const VERDICT_LABEL: Record<string, string> = {
  malicious: "恶意",
  suspicious: "可疑",
  benign: "可信",
  informational: "未知",
  clean: "—",
  reserved: "保留地址",
};
```

`VERDICT_STYLE` — add `reserved` (gray, distinct from `clean` and `informational`):

```typescript
export const VERDICT_STYLE: Record<string, string> = {
  malicious: "bg-red-500/15 text-red-300 ring-1 ring-red-500/30",
  suspicious: "bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30",
  benign: "bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30",
  informational: "bg-zinc-500/15 text-zinc-400 ring-1 ring-zinc-500/25",
  clean: "bg-zinc-700/40 text-zinc-500 ring-1 ring-zinc-600/40",
  reserved: "bg-zinc-600/30 text-zinc-300 ring-1 ring-zinc-500/40",
};
```

`VERDICT_RANK` — add `reserved: 0`:

```typescript
export const VERDICT_RANK: Record<string, number> = {
  malicious: 3, suspicious: 2, benign: 1, informational: 0, clean: 0,
  reserved: 0,
};
```

`threatSummary` — add the reserved short-circuit at the very top of the function body. Current first lines:

```typescript
export function threatSummary(r: LookupResult): {
  verdict: string;
  confidence: number;
  sourceCount: number;
  corroborated: boolean;
  conflict: boolean;
  hasThreats: boolean;
} {
  const cas = Object.values(r.classifications).filter((c) => c.detected && c.confidence > 0);
```

Insert immediately after the opening `{` and before `const cas`:

```typescript
  if (r.is_reserved) {
    return { verdict: "reserved", confidence: 0, sourceCount: 0,
      corroborated: false, conflict: false, hasThreats: false };
  }
  const cas = Object.values(r.classifications).filter((c) => c.detected && c.confidence > 0);
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd frontend && npx vitest run src/components/__tests__/threatDisplay.test.ts`
Expected: PASS (all threatDisplay tests).

- [ ] **Step 6: Type-check + lint**

Run: `cd frontend && npm run build`
Expected: build succeeds (`tsc -b` clean).

Run: `cd frontend && npm run lint`
Expected: no NEW errors in `api.ts` or `threatDisplay.ts` (total ≤ the 9-error baseline).

- [ ] **Step 7: Commit**

```bash
git add frontend/src/api.ts frontend/src/components/threatDisplay.ts frontend/src/components/__tests__/threatDisplay.test.ts
git commit -m "feat(frontend): model reserved verdict + LookupResult.is_reserved"
```

---

## Task 5: Frontend — render reserved rows in `ResultTable` (+ CSV verdict test)

**Files:**
- Modify: `frontend/src/components/ResultTable.tsx` (`VerdictCell` ~line 85; the IP `<td>` ~line 489; the expanded detail `<td>` ~line 527)
- Test: `frontend/src/components/__tests__/csvExport.test.ts` (add a test)
- Test: `frontend/src/components/__tests__/ResultTable.test.tsx` (create)

**Interfaces:**
- Consumes: `"reserved"` verdict from `threatSummary` (Task 4); `r.is_reserved`.
- Produces: reserved rows show a gray "保留地址" verdict badge, a muted IP cell, and (when expanded) a one-line notice instead of the detail panel. CSV `verdict` column emits `reserved` (automatic via `threatSummary` — this task only adds a test confirming it).

- [ ] **Step 1: Write the failing CSV test**

In `frontend/src/components/__tests__/csvExport.test.ts`, add inside `describe("buildCsv", ...)`:

```typescript
  it("writes 'reserved' verdict for reserved IPs", () => {
    const reserved = { ...r, is_reserved: true, classifications: {} };
    const row = buildCsv([reserved]).split("\n")[1];
    expect(row).toContain(",reserved,");
  });
```

- [ ] **Step 2: Write the failing ResultTable component test**

Create `frontend/src/components/__tests__/ResultTable.test.tsx`:

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ResultTable } from "../ResultTable";
import type { LookupResult } from "../../api";

const mf = <T,>(value: T, confidence = 95) => ({
  value, confidence, algorithm: "cascade" as const,
  sources: [{ source: "geo", value, reliability: 0.9, authoritative: true }],
});

const reserved: LookupResult = {
  ip: "10.0.0.1",
  country: mf("N/A", 0), asn: mf(0, 0), as_name: mf("N/A", 0),
  ip_range: mf("N/A", 0), is_isp: false, classifications: {},
  is_reserved: true,
};

describe("ResultTable reserved rows", () => {
  it("renders 保留地址 verdict for a reserved IP", () => {
    render(<ResultTable results={[reserved]} />);
    expect(screen.getAllByText("保留地址").length).toBeGreaterThanOrEqual(1);
  });
});
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd frontend && npx vitest run src/components/__tests__/csvExport.test.ts src/components/__tests__/ResultTable.test.tsx`
Expected: FAIL — CSV writes `clean` not `reserved` (no, actually `threatSummary` already returns `reserved` from Task 4, so the CSV test should PASS already — that's fine, it's a regression guard). The ResultTable test FAILs: `VerdictCell` renders `-` for reserved (because `summary.hasThreats` is false), so "保留地址" is not in the document.

- [ ] **Step 4: Render the reserved verdict badge in `VerdictCell`**

In `frontend/src/components/ResultTable.tsx`, `VerdictCell` currently starts:

```tsx
function VerdictCell({ summary }: { summary: ReturnType<typeof threatSummary> }) {
  const label = VERDICT_LABEL[summary.verdict] ?? "未知";
  const style = VERDICT_STYLE[summary.verdict] ?? VERDICT_STYLE.informational;
  const showConf = summary.verdict === "malicious" || summary.verdict === "suspicious";
  const tooltip = summary.hasThreats
    ? `${label}${showConf ? ` 置信度 ${summary.confidence}` : ""}${summary.sourceCount ? ` · ${summary.sourceCount} 源` : ""}${summary.corroborated ? " · 已印证" : ""}${summary.conflict ? " · 判定冲突" : ""}`
    : "";
  if (!summary.hasThreats) return <span className="text-zinc-700 text-[11px]">-</span>;
```

Add a reserved branch immediately before the `if (!summary.hasThreats)` line:

```tsx
  if (summary.verdict === "reserved") {
    return (
      <span title="保留地址 · 不可路由 · 未查询威胁情报"
        className={`inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-semibold ${VERDICT_STYLE.reserved}`}>
        保留地址
      </span>
    );
  }
  if (!summary.hasThreats) return <span className="text-zinc-700 text-[11px]">-</span>;
```

- [ ] **Step 5: Mute the IP cell for reserved rows**

Find the IP cell (inside `pageRows.map`, ~line 489):

```tsx
                  <td className="px-3 py-2 text-zinc-100 font-semibold">{r.ip}</td>
```

Change to dim the text when reserved:

```tsx
                  <td className={`px-3 py-2 font-semibold ${r.is_reserved ? "text-zinc-500" : "text-zinc-100"}`}>{r.ip}</td>
```

- [ ] **Step 6: Render a notice instead of the detail panel for expanded reserved rows**

Find the expanded detail cell (~line 527):

```tsx
                      <td colSpan={7} className="px-5 py-3 bg-zinc-900/60 border-b border-zinc-800/40">
                        <IpDetailPanel r={r} />
                      </td>
```

Change to conditionally render the notice:

```tsx
                      <td colSpan={7} className="px-5 py-3 bg-zinc-900/60 border-b border-zinc-800/40">
                        {r.is_reserved ? (
                          <div className="text-xs text-zinc-500">保留地址 · 不可路由 · 未查询威胁情报</div>
                        ) : (
                          <IpDetailPanel r={r} />
                        )}
                      </td>
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cd frontend && npx vitest run src/components/__tests__/csvExport.test.ts src/components/__tests__/ResultTable.test.tsx`
Expected: PASS.

- [ ] **Step 8: Type-check + lint**

Run: `cd frontend && npm run build`
Expected: build succeeds.

Run: `cd frontend && npm run lint`
Expected: no NEW errors in modified files (total ≤ 9 baseline).

- [ ] **Step 9: Commit**

```bash
git add frontend/src/components/ResultTable.tsx frontend/src/components/__tests__/csvExport.test.ts frontend/src/components/__tests__/ResultTable.test.tsx
git commit -m "feat(frontend): render reserved IP rows with notice"
```

---

## Task 6: Frontend — count reserved IPs separately in `SummaryBar`

**Files:**
- Modify: `frontend/src/components/ResultTable.tsx` (`SummaryBar` ~line 145 — also `export` it)
- Test: `frontend/src/components/__tests__/SummaryBar.test.tsx` (create)

**Interfaces:**
- Produces: `SummaryBar` (now exported) counts reserved IPs in a separate "保留地址" bucket and EXCLUDES them from the low/med/high-confidence tallies.

- [ ] **Step 1: Write the failing test**

Create `frontend/src/components/__tests__/SummaryBar.test.tsx`:

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { SummaryBar } from "../ResultTable";
import type { LookupResult } from "../../api";

const mf = <T,>(value: T, confidence = 95) => ({
  value, confidence, algorithm: "cascade" as const,
  sources: [{ source: "geo", value, reliability: 0.9, authoritative: true }],
});

const reserved: LookupResult = {
  ip: "10.0.0.1", country: mf("N/A", 0), asn: mf(0, 0),
  as_name: mf("N/A", 0), ip_range: mf("N/A", 0), is_isp: false,
  classifications: {}, is_reserved: true,
};

describe("SummaryBar reserved bucket", () => {
  it("counts reserved IPs as 保留地址, not as 低置信", () => {
    render(<SummaryBar results={[reserved]} />);
    expect(screen.getByText("保留地址")).toBeInTheDocument();
    expect(screen.queryByText(/低置信/)).not.toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd frontend && npx vitest run src/components/__tests__/SummaryBar.test.tsx`
Expected: FAIL — `SummaryBar` is not exported (import error), and even if it were, a reserved IP has `lowestConfidence` 0 so it would be counted as "1 低置信".

- [ ] **Step 3: Update `SummaryBar` to track and render a reserved bucket**

In `frontend/src/components/ResultTable.tsx`, first export it — change:

```tsx
function SummaryBar({ results }: { results: LookupResult[] }) {
```

to:

```tsx
export function SummaryBar({ results }: { results: LookupResult[] }) {
```

Inside the `useMemo` stats block, the tallies currently are:

```tsx
    let ispCount = 0;
    let lowConf = 0;
    let medConf = 0;
    let highConf = 0;

    for (const r of results) {
      for (const type of Object.keys(r.classifications)) {
        classTotals[type] = (classTotals[type] || 0) + 1;
      }
      if (r.is_isp) ispCount++;
      const c = lowestConfidence(r);
      if (c < 30) lowConf++;
      else if (c < 70) medConf++;
      else highConf++;
    }

    return { classTotals, ispCount, lowConf, medConf, highConf };
```

Change to add `reservedCount` and skip reserved IPs in the tally:

```tsx
    let ispCount = 0;
    let lowConf = 0;
    let medConf = 0;
    let highConf = 0;
    let reservedCount = 0;

    for (const r of results) {
      if (r.is_reserved) {
        reservedCount++;
        continue;
      }
      for (const type of Object.keys(r.classifications)) {
        classTotals[type] = (classTotals[type] || 0) + 1;
      }
      if (r.is_isp) ispCount++;
      const c = lowestConfidence(r);
      if (c < 30) lowConf++;
      else if (c < 70) medConf++;
      else highConf++;
    }

    return { classTotals, ispCount, lowConf, medConf, highConf, reservedCount };
```

Update the early-return guard to also account for reserved. Find:

```tsx
  if (activeClasses.length === 0 && stats.ispCount === 0 && stats.lowConf === 0 && stats.medConf === 0) {
```

Change to:

```tsx
  if (activeClasses.length === 0 && stats.ispCount === 0 && stats.lowConf === 0 && stats.medConf === 0 && stats.reservedCount === 0) {
```

Add the reserved stat. Find the `stats.ispCount > 0` block (the last stat before the closing `</div>`):

```tsx
      {stats.ispCount > 0 && (
        <>
          <span className="text-zinc-600">|</span>
          <span className="flex items-center gap-1">
            <span className="rounded bg-emerald-500/15 px-1 py-0.5 text-[10px] font-medium text-emerald-400 ring-1 ring-emerald-500/25">
              ISP
            </span>
            <span className="text-zinc-500">{stats.ispCount}</span>
          </span>
        </>
      )}
    </div>
```

Insert a reserved block before the final `</div>`:

```tsx
      {stats.ispCount > 0 && (
        <>
          <span className="text-zinc-600">|</span>
          <span className="flex items-center gap-1">
            <span className="rounded bg-emerald-500/15 px-1 py-0.5 text-[10px] font-medium text-emerald-400 ring-1 ring-emerald-500/25">
              ISP
            </span>
            <span className="text-zinc-500">{stats.ispCount}</span>
          </span>
        </>
      )}
      {stats.reservedCount > 0 && (
        <>
          <span className="text-zinc-600">|</span>
          <span className="flex items-center gap-1">
            <span className="rounded bg-zinc-600/40 px-1 py-0.5 text-[10px] font-medium text-zinc-400 ring-1 ring-zinc-500/30">
              保留地址
            </span>
            <span className="text-zinc-500">{stats.reservedCount}</span>
          </span>
        </>
      )}
    </div>
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd frontend && npx vitest run src/components/__tests__/SummaryBar.test.tsx`
Expected: PASS.

- [ ] **Step 5: Run the full frontend suite**

Run: `cd frontend && npm test`
Expected: PASS (all frontend tests).

- [ ] **Step 6: Type-check + lint**

Run: `cd frontend && npm run build`
Expected: build succeeds.

Run: `cd frontend && npm run lint`
Expected: no NEW errors (total ≤ 9 baseline).

- [ ] **Step 7: Commit**

```bash
git add frontend/src/components/ResultTable.tsx frontend/src/components/__tests__/SummaryBar.test.tsx
git commit -m "feat(frontend): count reserved IPs separately in SummaryBar"
```

---

## Task 7: Frontend — make "Expand disagreements" a toggle

**Files:**
- Modify: `frontend/src/components/ResultTable.tsx` (`expandDisagreements` ~line 389; the button ~line 428)
- Test: `frontend/src/components/__tests__/ResultTable.test.tsx` (add a describe block — created in Task 5)

**Interfaces:**
- Produces: clicking "Expand disagreements" expands low-confidence (non-reserved) rows; clicking again (now labeled "Collapse disagreements", amber) collapses them. Manually-expanded unrelated rows are preserved. Reserved IPs are excluded from the disagreement set.

- [ ] **Step 1: Write the failing test**

In `frontend/src/components/__tests__/ResultTable.test.tsx` (created in Task 5), make two edits:

First, merge `fireEvent` into the existing import at the top of the file — change `import { render, screen } from "@testing-library/react";` to:

```tsx
import { render, screen, fireEvent } from "@testing-library/react";
```

Then add a second fixture and describe block at the bottom of the file:

```tsx
const lowConf: LookupResult = {
  ip: "203.0.113.5", country: mf("US", 50), asn: mf(64500, 50),
  as_name: mf("Example", 50), ip_range: mf("203.0.113.0/24", 50),
  is_isp: false, classifications: {},
};

describe("Expand disagreements toggle", () => {
  it("expands on first click, collapses on second", async () => {
    render(<ResultTable results={[lowConf]} />);
    // collapsed initially — detail panel not shown
    expect(screen.queryByText("威胁明细")).not.toBeInTheDocument();

    const expand = screen.getByRole("button", { name: /expand disagreements/i });
    fireEvent.click(expand);
    expect(await screen.findByText("威胁明细")).toBeInTheDocument();

    // button flipped to Collapse; clicking it collapses
    const collapse = screen.getByRole("button", { name: /collapse disagreements/i });
    fireEvent.click(collapse);
    expect(screen.getByRole("button", { name: /expand disagreements/i })).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd frontend && npx vitest run src/components/__tests__/ResultTable.test.tsx`
Expected: FAIL — after the first click, the detail expands (test reaches `findByText("威胁明细")`), but there is no "Collapse disagreements" button (the button label never changes), so `getByRole("collapse disagreements")` throws.

- [ ] **Step 3: Convert `expandDisagreements` to a toggle**

In `frontend/src/components/ResultTable.tsx`, find the current handler (~line 389):

```tsx
  const expandDisagreements = () => {
    const ips = filtered
      .filter((r) => lowestConfidence(r) < 70)
      .map((r) => r.ip);
    setExpanded(new Set(ips));
  };
```

Replace it with the derived state + toggle handler (note: reserved IPs are excluded from the disagreement set):

```tsx
  const disagreementIps = useMemo(
    () => filtered
      .filter((r) => !r.is_reserved && lowestConfidence(r) < 70)
      .map((r) => r.ip),
    [filtered],
  );
  const allDisagreementsExpanded =
    disagreementIps.length > 0 && disagreementIps.every((ip) => expanded.has(ip));

  const toggleDisagreements = () => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (allDisagreementsExpanded) disagreementIps.forEach((ip) => next.delete(ip));
      else disagreementIps.forEach((ip) => next.add(ip));
      return next;
    });
  };
```

Then update the button. Find the current button (~line 428):

```tsx
        <button
          onClick={expandDisagreements}
          className="rounded-md bg-zinc-800 px-2.5 py-1.5 text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
        >
          Expand disagreements
        </button>
```

Replace with the toggle button (amber + label flip when all disagreements are expanded, mirroring the adjacent "Disagreements first" button):

```tsx
        <button
          onClick={toggleDisagreements}
          className={`rounded-md px-2.5 py-1.5 text-xs transition-colors ${
            allDisagreementsExpanded
              ? "bg-amber-500/15 text-amber-400 ring-1 ring-amber-500/25"
              : "bg-zinc-800 text-zinc-500 hover:text-zinc-300"
          }`}
        >
          {allDisagreementsExpanded ? "Collapse disagreements" : "Expand disagreements"}
        </button>
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd frontend && npx vitest run src/components/__tests__/ResultTable.test.tsx`
Expected: PASS (both the reserved-row test from Task 5 and the new toggle test).

- [ ] **Step 5: Run the full frontend suite + type-check + lint**

Run: `cd frontend && npm test`
Expected: PASS.

Run: `cd frontend && npm run build`
Expected: build succeeds.

Run: `cd frontend && npm run lint`
Expected: no NEW errors (total ≤ 9 baseline).

- [ ] **Step 6: Commit**

```bash
git add frontend/src/components/ResultTable.tsx frontend/src/components/__tests__/ResultTable.test.tsx
git commit -m "fix(frontend): make Expand disagreements a toggle"
```

---

## Final verification

After Task 7:

- [ ] **Full backend suite:** `cd backend && .venv/bin/python -m pytest -q` → all green.
- [ ] **Full frontend suite:** `cd frontend && npm test` → all green.
- [ ] **Frontend build:** `cd frontend && npm run build` → succeeds.
- [ ] **Manual smoke test:** start the app, look up `10.0.0.1` — the row shows a gray "保留地址" badge (not "恶意"), the summary shows a "保留地址 1" bucket (no red "低置信"), expanding the row shows "保留地址 · 不可路由 · 未查询威胁情报". Then look up `8.8.8.8` to confirm normal verdicts still render. Then click "Expand disagreements" twice to confirm toggle behavior.
