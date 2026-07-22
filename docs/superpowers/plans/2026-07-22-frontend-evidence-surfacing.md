# Frontend Evidence Surfacing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface the backend-preserved Evidence richness in the UI (4-zone tiered expand) and CSV export, so the source-authoring refactor's lossless fields are actually visible.

**Architecture:** Extract the expanded-detail subtree from `ResultTable.tsx` (772 lines, near its ceiling) into focused single-responsibility components (`SourceDetailRow` → `ClassificationBlock` → `IpDetailPanel`), fed by a shared leaf module `threatDisplay.ts` (breaks the import cycle). Add the dropped per-source fields (reliability, per-source malware, comment, tags, reporter_count, full extra) plus assessment-level `reporter_total`. CSV gains 5 aggregated columns.

**Tech Stack:** React 19, TypeScript 6 (`verbatimModuleSyntax`, `noUnusedLocals`, `erasableSyntaxOnly`), Vite 8, Tailwind 4, motion 12. Testing: vitest + @testing-library/react + jsdom (added by this plan).

## Global Constraints

- **Backend unchanged.** Do not edit anything under `backend/`. The 5 new CSV columns are derived purely from existing serialized fields.
- **UI copy stays Chinese where it already is** (判定 labels: 恶意/可疑/可信/未知; section header 威胁明细; field labels 国家/ASN/机构 / ISP/网段; badges 已印证/判定冲突/·N上报/未命中). New strings follow the same convention.
- **TS strictness (tsconfig.app.json):** `verbatimModuleSyntax` (use `import type` for types), `noUnusedLocals` + `noUnusedParameters` (no unused imports/vars), `erasableSyntaxOnly` (no TS enums/namespaces), `"include": ["src"]` (every `.test.tsx` is type-checked by `npm run build`).
- **One-component-per-file** is the repo convention (`DbStatusBar.tsx`, `ExportCsv.tsx`, etc.). Follow it for the new components.
- **Verification gate every task:** `cd frontend && npm run build` (runs `tsc -b`) AND `npm run lint` AND `npm test` must all be green before a task's commit.
- **Deferred (do NOT implement):** `isp` scalar slot, asset `extra`, `last_seen` — all backend-side (see spec Section C).

---

## File Structure

| File | Status | Responsibility |
|---|---|---|
| `frontend/vitest.config.ts` | Create | Vitest config: jsdom env, React plugin, setup file |
| `frontend/src/test/setup.ts` | Create | Registers jest-dom matchers for vitest |
| `frontend/src/__tests__/sanity.test.tsx` | Create | Proves the harness runs |
| `frontend/tsconfig.app.json` | Modify | Add jest-dom types so `tsc -b` type-checks test matchers |
| `frontend/package.json` | Modify (via npm) | devDeps + `test`/`test:run` scripts |
| `frontend/src/components/threatDisplay.ts` | Create | Leaf module: shared verdict/confidence/label helpers + `threatSummary` |
| `frontend/src/components/ResultTable.tsx` | Modify | Drop moved helpers (Task 2); delete old panel + wire `IpDetailPanel` (Task 6) |
| `frontend/src/components/SourceDetailRow.tsx` | Create | Z3 one-source detail + Z4 extra toggle |
| `frontend/src/components/ClassificationBlock.tsx` | Create | Z2 header (+reporter_total) + Z3 rows |
| `frontend/src/components/IpDetailPanel.tsx` | Create | Z1 identity + 威胁明细 orchestration |
| `frontend/src/components/csvExport.ts` | Create | Pure `aggregateThreatDepth` + `buildCsv` (keeps lint's react-refresh rule happy by separating non-component exports) |
| `frontend/src/components/ExportCsv.tsx` | Modify | Use `csvExport` helpers; component stays thin |

---

### Task 1: Vitest + Testing Library harness

**Files:**
- Modify: `frontend/package.json` (devDeps + scripts, via `npm install`)
- Create: `frontend/vitest.config.ts`
- Create: `frontend/src/test/setup.ts`
- Modify: `frontend/tsconfig.app.json:7` (`types` array)
- Create: `frontend/src/__tests__/sanity.test.tsx`

**Interfaces:**
- Produces: a working `npm test` command; jsdom environment; jest-dom matchers available to all `*.test.tsx` under `src/`.

- [ ] **Step 1: Install dev dependencies**

Run from `frontend/`:
```bash
npm install -D vitest @testing-library/react @testing-library/jest-dom @testing-library/user-event jsdom
```
Expected: packages added under `devDependencies`. If npm reports a peer-dependency conflict with Vite 8, install the vitest release that declares Vite-8 support: `npm info vitest peerDependencies.vite` to see the supported range, then `npm install -D vitest@<that-release>`. Do NOT use `--legacy-peer-deps` to paper over it.

- [ ] **Step 2: Add test scripts to `package.json`**

In `frontend/package.json`, add to `"scripts"` (keep existing entries):
```json
"test": "vitest run",
"test:watch": "vitest"
```
(`vitest run` = single pass, exits non-zero on failure — correct for the per-task gate.)

- [ ] **Step 3: Create `frontend/vitest.config.ts`**

```ts
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
  },
});
```

- [ ] **Step 4: Create `frontend/src/test/setup.ts`**

```ts
import "@testing-library/jest-dom/vitest";
```

- [ ] **Step 5: Extend `tsconfig.app.json` types so `tsc -b` knows the matchers**

Change line 7 of `frontend/tsconfig.app.json` from:
```json
    "types": ["vite/client"],
```
to:
```json
    "types": ["vite/client", "@testing-library/jest-dom"],
```
Tests import `describe/it/expect` explicitly from `"vitest"`, so no globals type entry is needed.

- [ ] **Step 6: Create the sanity test `frontend/src/__tests__/sanity.test.tsx`**

```tsx
import { describe, it, expect } from "vitest";

describe("sanity", () => {
  it("vitest + jsdom works", () => {
    const el = document.createElement("div");
    el.textContent = "ok";
    expect(el).toBeInTheDocument();
    expect(el.textContent).toBe("ok");
  });
});
```

- [ ] **Step 7: Run the harness, expect green**

Run from `frontend/`:
```bash
npm test
```
Expected: `1 passed` (the sanity test). Then confirm the production build still type-checks with the new test file in `src`:
```bash
npm run build
```
Expected: `tsc -b` + vite build succeed (the `@testing-library/jest-dom` types entry is what keeps this green). Also `npm run lint` must pass.

- [ ] **Step 8: Commit**

```bash
git add frontend/package.json frontend/package-lock.json frontend/vitest.config.ts frontend/src/test/setup.ts frontend/tsconfig.app.json frontend/src/__tests__/sanity.test.tsx
git commit -m "test(frontend): add vitest + testing-library/jsdom harness"
```

---

### Task 2: Extract shared `threatDisplay.ts` (behavior-preserving)

**Why:** The new components (`ClassificationBlock`, `IpDetailPanel`) need `classLabel`, `VERDICT_LABEL/STYLE`, `confTextColor`, `ALGORITHM_ICONS`. Those currently live in `ResultTable.tsx`, which will import `IpDetailPanel` (Task 6) — so importing them back from `ResultTable` creates a cycle. Move the shared surface to a leaf module first.

**Files:**
- Create: `frontend/src/components/threatDisplay.ts`
- Create: `frontend/src/components/__tests__/threatDisplay.test.ts`
- Modify: `frontend/src/components/ResultTable.tsx` (delete moved defs, add import)
- Modify: `frontend/src/components/ExportCsv.tsx` (repoint import, already consumes `threatSummary`/`classLabel`/`familyShort`)

**Interfaces:**
- Produces: `threatDisplay.ts` exporting `confColor`, `confTextColor`, `VERDICT_LABEL`, `VERDICT_STYLE`, `VERDICT_RANK`, `ALGORITHM_ICONS`, `normType`, `classLabel`, `familyShort`, `threatSummary`.

- [ ] **Step 1: Write the failing test `frontend/src/components/__tests__/threatDisplay.test.ts`**

```ts
import { describe, it, expect } from "vitest";
import {
  classLabel, familyShort, threatSummary, confTextColor, normType,
} from "../threatDisplay";
import type { LookupResult } from "../../api";

const mf = (value: string, confidence = 95) => ({
  value, confidence, algorithm: "cascade" as const,
  sources: [{ source: "geo", value, reliability: 0.9, authoritative: true }],
});

const dirty: LookupResult = {
  ip: "1.1.1.1",
  country: mf("US"), asn: mf("1"), as_name: mf("X"), ip_range: mf("1.0.0.0/24"),
  is_isp: false,
  classifications: {
    scanner: { type: "scanner", verdict: "suspicious", detected: true, confidence: 50,
      algorithm: "corroboration", corroborated: false, reporter_total: 0,
      verdict_conflict: false, malware_names: [], details: [],
      sources: [{ source: "a", value: true, reliability: 0.5, authoritative: false }] },
    c2_server: { type: "c2_server", verdict: "malicious", detected: true, confidence: 90,
      algorithm: "corroboration", corroborated: true, reporter_total: 2,
      verdict_conflict: true, malware_names: ["win.x"], details: [],
      sources: [{ source: "b", value: true, reliability: 0.8, authoritative: false }] },
  },
  attributes: {}, is_whitelisted: false, whitelist_notes: [],
};

describe("threatDisplay", () => {
  it("classLabel maps known types and normalizes hyphens", () => {
    expect(classLabel("c2_server")).toBe("C2");
    expect(classLabel("brute-force")).toBe("暴力破解");
    expect(classLabel("novel_thing")).toBe("novel thing");
  });
  it("normType replaces hyphens with underscores", () => {
    expect(normType("brute-force")).toBe("brute_force");
  });
  it("familyShort strips os prefix", () => {
    expect(familyShort("win.vidar")).toBe("vidar");
    expect(familyShort("remcos")).toBe("remcos");
  });
  it("confTextColor thresholds", () => {
    expect(confTextColor(95)).toBe("text-emerald-400");
    expect(confTextColor(50)).toBe("text-amber-400");
    expect(confTextColor(10)).toBe("text-red-400");
  });
  it("threatSummary picks worst verdict, counts sources, flags corroborated+conflict", () => {
    const s = threatSummary(dirty);
    expect(s.verdict).toBe("malicious");
    expect(s.confidence).toBe(90);
    expect(s.sourceCount).toBe(2);
    expect(s.corroborated).toBe(true);
    expect(s.conflict).toBe(true);
    expect(s.hasThreats).toBe(true);
  });
  it("threatSummary reports clean when nothing detected", () => {
    const clean = { ...dirty, classifications: {} };
    const s = threatSummary(clean);
    expect(s.hasThreats).toBe(false);
    expect(s.verdict).toBe("clean");
  });
});
```

- [ ] **Step 2: Run the test, verify it fails**

```bash
cd frontend && npm test -- threatDisplay
```
Expected: FAIL — `Failed to resolve import "../threatDisplay"`.

- [ ] **Step 3: Create `frontend/src/components/threatDisplay.ts`**

Copy these definitions verbatim (they are the exact current bodies from `ResultTable.tsx`):

```ts
import type { LookupResult } from "../api";

export function confColor(conf: number): string {
  if (conf >= 70) return "bg-emerald-500";
  if (conf >= 30) return "bg-amber-500";
  return "bg-red-500";
}

export function confTextColor(conf: number): string {
  if (conf >= 70) return "text-emerald-400";
  if (conf >= 30) return "text-amber-400";
  return "text-red-400";
}

export const VERDICT_LABEL: Record<string, string> = {
  malicious: "恶意",
  suspicious: "可疑",
  benign: "可信",
  informational: "未知",
  clean: "—",
};

export const VERDICT_STYLE: Record<string, string> = {
  malicious: "bg-red-500/15 text-red-300 ring-1 ring-red-500/30",
  suspicious: "bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30",
  benign: "bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30",
  informational: "bg-zinc-500/15 text-zinc-400 ring-1 ring-zinc-500/25",
  clean: "bg-zinc-700/40 text-zinc-500 ring-1 ring-zinc-600/40",
};

export const VERDICT_RANK: Record<string, number> = {
  malicious: 3, suspicious: 2, benign: 1, informational: 0, clean: 0,
};

export const ALGORITHM_ICONS: Record<string, string> = {
  cascade: "🔑",
  voting: "📊",
  pcr6: "⚠️",
  authority: "🏛️",
  specificity: "🎯",
  corroboration: "🤝",
};

const CLASS_LABELS: Record<string, string> = {
  "c2_server": "C2",
  botnet_cc: "C2",
  scanner: "扫描",
  brute_force: "暴力破解",
  malware: "恶意软件",
  blacklist: "黑名",
  tor: "Tor",
  proxy: "代理",
  hosting: "机房",
  vpn: "VPN",
};

export function normType(type: string): string {
  return type.replace(/-/g, "_");
}

export function classLabel(type: string): string {
  const t = normType(type);
  return CLASS_LABELS[t] ?? t.replace(/_/g, " ");
}

export function familyShort(name: string): string {
  return name.replace(/^(win|linux|mac|osx|android|ios|trojan|worm|backdoor)[._-]/i, "");
}

export function threatSummary(r: LookupResult): {
  verdict: string;
  confidence: number;
  sourceCount: number;
  corroborated: boolean;
  conflict: boolean;
  hasThreats: boolean;
} {
  const cas = Object.values(r.classifications).filter((c) => c.detected && c.confidence > 0);
  if (cas.length === 0) {
    return { verdict: "clean", confidence: 0, sourceCount: 0, corroborated: false, conflict: false, hasThreats: false };
  }
  let worst = cas[0];
  for (const c of cas) {
    if ((VERDICT_RANK[c.verdict] ?? 0) > (VERDICT_RANK[worst.verdict] ?? 0)) worst = c;
  }
  const worstVerdict = worst.verdict;
  const confidence = Math.max(...cas.filter((c) => c.verdict === worstVerdict).map((c) => c.confidence));
  const sources = new Set<string>();
  for (const c of cas) for (const s of c.sources) sources.add(s.source);
  return {
    verdict: worstVerdict,
    confidence,
    sourceCount: sources.size,
    corroborated: cas.some((c) => c.corroborated),
    conflict: cas.some((c) => c.verdict_conflict),
    hasThreats: true,
  };
}
```

- [ ] **Step 4: Delete the moved definitions from `ResultTable.tsx` and import them**

In `frontend/src/components/ResultTable.tsx`:
- Delete the local definitions of: `confColor`, `confTextColor`, `VERDICT_LABEL`, `VERDICT_STYLE`, `VERDICT_RANK`, `ALGORITHM_ICONS`, `CLASS_LABELS`, `normType`, `classLabel`, `familyShort`, `threatSummary` (lines ~12–165). Keep `INFRA_TYPES`, `classPalette`, `isInfra`, `CLASS_PALETTE`, `INFRA_FALLBACK`, `BEHAVIORAL_FALLBACK`, `assetBadges`, `ASSET_LABELS`, etc.
- Add to the existing imports at the top:
```ts
import {
  confColor, confTextColor, VERDICT_LABEL, VERDICT_STYLE, VERDICT_RANK,
  ALGORITHM_ICONS, normType, classLabel, familyShort, threatSummary,
} from "./threatDisplay";
```
(`normType` is still used by `ResultTable`'s `isInfra`/`classPalette`; `classLabel`/`familyShort` by `ThreatTags`/`SummaryBar`; the rest by `VerdictCell`/`FieldDetail`/etc. All ten are consumed in-file, so `noUnusedLocals` stays satisfied.)

- [ ] **Step 5: Repoint `ExportCsv.tsx` import**

In `frontend/src/components/ExportCsv.tsx` change:
```ts
import { threatSummary, classLabel, familyShort } from "./ResultTable";
```
to:
```ts
import { threatSummary, classLabel, familyShort } from "./threatDisplay";
```

- [ ] **Step 6: Run tests + build + lint, expect green**

```bash
cd frontend && npm test && npm run build && npm run lint
```
Expected: `threatDisplay` tests pass; build/lint green (the move is behavior-preserving — `ResultTable` and `ExportCsv` resolve the same symbols via the new module).

- [ ] **Step 7: Commit**

```bash
git add frontend/src/components/threatDisplay.ts frontend/src/components/__tests__/threatDisplay.test.ts frontend/src/components/ResultTable.tsx frontend/src/components/ExportCsv.tsx
git commit -m "refactor(frontend): extract shared threatDisplay helpers to leaf module"
```

---

### Task 3: `SourceDetailRow` (Z3 per-source detail + Z4 extra toggle)

**Files:**
- Create: `frontend/src/components/SourceDetailRow.tsx`
- Create: `frontend/src/components/__tests__/SourceDetailRow.test.tsx`

**Interfaces:**
- Consumes: `ClassificationDetail` from `../api`.
- Produces: `SourceDetailRow({ detail: ClassificationDetail })` — renders `source · rel {reliability}`, plus optional `native_type` (from `extra.native_type`), `native_confidence`, `first_seen`, per-source `malware_name`, `comment`, `tags`, `reporter_count`, and a collapsible full-`extra` JSON block.

- [ ] **Step 1: Write the failing test `frontend/src/components/__tests__/SourceDetailRow.test.tsx`**

```tsx
import { describe, it, expect } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { SourceDetailRow } from "../SourceDetailRow";
import type { ClassificationDetail } from "../../api";

const base: ClassificationDetail = { source: "otx", reliability: 0.9 };

describe("SourceDetailRow", () => {
  it("always renders source and reliability", () => {
    render(<SourceDetailRow detail={base} />);
    expect(screen.getByText(/otx/)).toBeInTheDocument();
    expect(screen.getByText(/rel 0\.9/)).toBeInTheDocument();
  });

  it("renders all optional fields when present", () => {
    const d: ClassificationDetail = {
      ...base,
      malware_name: "remcos",
      comment: "sinkholed by abuse.ch",
      tags: ["c2", "botnet"],
      reporter_count: 4,
      native_confidence: 85,
      first_seen: "2026-07-01T00:00:00+00:00",
      extra: { native_type: "PUB" },
    };
    render(<SourceDetailRow detail={d} />);
    expect(screen.getByText(/malware: remcos/)).toBeInTheDocument();
    expect(screen.getByText(/reporters: 4/)).toBeInTheDocument();
    expect(screen.getByText(/\[c2\]/)).toBeInTheDocument();
    expect(screen.getByText(/\[PUB\]/)).toBeInTheDocument();
    expect(screen.getByText(/native 85/)).toBeInTheDocument();
    expect(screen.getByText(/first 2026-07-01/)).toBeInTheDocument();
  });

  it("omits optional lines and the extra toggle when absent", () => {
    render(<SourceDetailRow detail={base} />);
    expect(screen.queryByText(/malware:/)).not.toBeInTheDocument();
    expect(screen.queryByText(/reporters:/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("truncates long comments and exposes the full text via title", () => {
    const long = "x".repeat(60);
    const d: ClassificationDetail = { ...base, comment: long };
    render(<SourceDetailRow detail={d} />);
    const node = screen.getByText(/comment:/);
    expect(node.getAttribute("title")).toBe(long);
    expect(node.textContent).toContain("…");
  });

  it("toggles the extra JSON block", () => {
    const d: ClassificationDetail = {
      ...base,
      extra: { foo: "bar", n: 1, b: true },
    };
    render(<SourceDetailRow detail={d} />);
    const toggle = screen.getByRole("button", { name: /extra 3 keys/i });
    expect(screen.queryByText(/"foo"/)).not.toBeInTheDocument();
    fireEvent.click(toggle);
    expect(screen.getByText(/"foo"/)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run, verify it fails**

```bash
cd frontend && npm test -- SourceDetailRow
```
Expected: FAIL — `Failed to resolve import "../SourceDetailRow"`.

- [ ] **Step 3: Create `frontend/src/components/SourceDetailRow.tsx`**

```tsx
import { useState } from "react";
import type { ClassificationDetail } from "../api";

function fmtRel(r: number): string {
  return String(Math.round(r * 100) / 100);
}

function fmtDate(iso: string): string {
  return iso.slice(0, 10);
}

export function SourceDetailRow({ detail: d }: { detail: ClassificationDetail }) {
  const [showExtra, setShowExtra] = useState(false);
  const nativeType = d.extra?.native_type;
  const extraKeys = d.extra ? Object.keys(d.extra) : [];
  const hasExtra = extraKeys.length > 0;
  const hasTags = !!(d.tags && d.tags.length > 0);

  return (
    <div className="text-[10px] leading-relaxed">
      <div>
        <span className="text-zinc-600">{d.source}</span>
        <span className="text-zinc-700"> · rel {fmtRel(d.reliability)}</span>
        {nativeType != null && (
          <span className="text-zinc-500 ml-1" title="源原生类型">[{String(nativeType)}]</span>
        )}
        {d.native_confidence != null && (
          <span className="text-zinc-500 ml-1">native {d.native_confidence}</span>
        )}
        {d.first_seen && (
          <span className="text-zinc-700 ml-1">first {fmtDate(d.first_seen)}</span>
        )}
      </div>

      {(d.malware_name || d.comment) && (
        <div className="ml-3">
          {d.malware_name && (
            <span className="text-purple-400 font-mono">malware: {d.malware_name} </span>
          )}
          {d.comment && (
            <span className="text-zinc-500" title={d.comment}>
              comment: "{d.comment.length > 40 ? d.comment.slice(0, 40) + "…" : d.comment}"
            </span>
          )}
        </div>
      )}

      {(hasTags || d.reporter_count != null) && (
        <div className="ml-3">
          {hasTags && (
            <span className="mr-2">
              {d.tags!.map((t) => (
                <span key={t} className="rounded bg-zinc-700/40 px-1 py-px mr-0.5 text-zinc-400">[{t}]</span>
              ))}
            </span>
          )}
          {d.reporter_count != null && (
            <span className="text-zinc-500">reporters: {d.reporter_count}</span>
          )}
        </div>
      )}

      {hasExtra && (
        <div className="ml-3">
          <button
            type="button"
            onClick={() => setShowExtra((v) => !v)}
            className="text-zinc-600 hover:text-zinc-400"
          >
            {showExtra ? "▾" : "▸"} extra {extraKeys.length} keys
          </button>
          {showExtra && (
            <pre className="mt-0.5 text-zinc-500 whitespace-pre-wrap break-all">
              {JSON.stringify(d.extra, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 4: Run, verify it passes**

```bash
cd frontend && npm test -- SourceDetailRow && npm run build && npm run lint
```
Expected: 5 passed; build/lint green.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/SourceDetailRow.tsx frontend/src/components/__tests__/SourceDetailRow.test.tsx
git commit -m "feat(frontend): SourceDetailRow renders per-source evidence (comment/tags/reporter/extra)"
```

---

### Task 4: `ClassificationBlock` (Z2 header + reporter_total + Z3 rows)

**Files:**
- Create: `frontend/src/components/ClassificationBlock.tsx`
- Create: `frontend/src/components/__tests__/ClassificationBlock.test.tsx`

**Interfaces:**
- Consumes: `ClassificationAssessment` from `../api`; `classLabel`, `VERDICT_LABEL`, `VERDICT_STYLE`, `confTextColor`, `ALGORITHM_ICONS` from `./threatDisplay`; `SourceDetailRow` from `./SourceDetailRow`.
- Produces: `ClassificationBlock({ type: string; ca: ClassificationAssessment })`.

- [ ] **Step 1: Write the failing test `frontend/src/components/__tests__/ClassificationBlock.test.tsx`**

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ClassificationBlock } from "../ClassificationBlock";
import type { ClassificationAssessment } from "../../api";

const ca: ClassificationAssessment = {
  type: "c2_server",
  verdict: "malicious",
  detected: true,
  confidence: 92,
  algorithm: "corroboration",
  corroborated: true,
  reporter_total: 4,
  verdict_conflict: false,
  malware_names: ["win.vidar"],
  details: [
    { source: "otx", reliability: 0.9, malware_name: "remcos" },
    { source: "threatfox", reliability: 0.7 },
  ],
  sources: [],
};

describe("ClassificationBlock", () => {
  it("renders Z2 header with label, verdict, and reporter_total", () => {
    render(<ClassificationBlock type="c2_server" ca={ca} />);
    expect(screen.getByText("C2")).toBeInTheDocument();
    expect(screen.getByText("恶意")).toBeInTheDocument();
    expect(screen.getByText(/·4上报/)).toBeInTheDocument();
    expect(screen.getByText(/已印证/)).toBeInTheDocument();
  });

  it("renders aggregated malware family chips", () => {
    render(<ClassificationBlock type="c2_server" ca={ca} />);
    expect(screen.getByText("win.vidar")).toBeInTheDocument();
  });

  it("renders one SourceDetailRow per detail entry", () => {
    render(<ClassificationBlock type="c2_server" ca={ca} />);
    expect(screen.getAllByText(/otx/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/threatfox/)).toBeInTheDocument();
  });

  it("omits the 上报 suffix when reporter_total is 0", () => {
    const zero = { ...ca, reporter_total: 0 };
    render(<ClassificationBlock type="c2_server" ca={zero} />);
    expect(screen.queryByText(/上报/)).not.toBeInTheDocument();
  });

  it("shows 判定冲突 badge when verdict_conflict", () => {
    const conflicted = { ...ca, verdict_conflict: true };
    render(<ClassificationBlock type="c2_server" ca={conflicted} />);
    expect(screen.getByText(/判定冲突/)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run, verify it fails**

```bash
cd frontend && npm test -- ClassificationBlock
```
Expected: FAIL — `Failed to resolve import "../ClassificationBlock"`.

- [ ] **Step 3: Create `frontend/src/components/ClassificationBlock.tsx`**

```tsx
import type { ClassificationAssessment } from "../api";
import {
  classLabel, VERDICT_LABEL, VERDICT_STYLE, confTextColor, ALGORITHM_ICONS,
} from "./threatDisplay";
import { SourceDetailRow } from "./SourceDetailRow";

export function ClassificationBlock({ type, ca }: { type: string; ca: ClassificationAssessment }) {
  return (
    <div>
      <div className="flex items-center gap-1.5 flex-wrap">
        <span className={`inline-block h-1.5 w-1.5 rounded-full ${ca.detected ? "bg-orange-400" : "bg-zinc-600"}`} />
        <span className="text-[11px] text-zinc-400 font-medium">{classLabel(type)}</span>
        <span className={`rounded px-1 py-px text-[10px] font-medium ${VERDICT_STYLE[ca.verdict] ?? VERDICT_STYLE.informational}`}>
          {VERDICT_LABEL[ca.verdict] ?? ca.verdict}
        </span>
        <span className={`text-[10px] ${confTextColor(ca.confidence)}`}>{ca.confidence}</span>
        <span className="text-[10px] text-zinc-600">{ALGORITHM_ICONS[ca.algorithm] ?? ca.algorithm}</span>
        {ca.corroborated && (
          <span className="text-[10px] text-amber-400" title="2+ 独立源印证">已印证</span>
        )}
        {ca.verdict_conflict && (
          <span className="text-[10px] text-red-400" title="源之间判定冲突">判定冲突</span>
        )}
        {ca.reporter_total > 0 && (
          <span className="text-[10px] text-zinc-500">·{ca.reporter_total}上报</span>
        )}
      </div>

      {ca.malware_names.length > 0 && (
        <div className="ml-3 mt-1 flex flex-wrap gap-1">
          {ca.malware_names.map((m) => (
            <span key={m} className="rounded bg-purple-500/10 px-1 py-px text-[10px] text-purple-400 font-mono">{m}</span>
          ))}
        </div>
      )}

      {ca.details.length > 0 && (
        <div className="ml-3 mt-1 space-y-1">
          {ca.details.map((d, idx) => (
            <SourceDetailRow key={d.source + idx} detail={d} />
          ))}
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 4: Run, verify it passes**

```bash
cd frontend && npm test -- ClassificationBlock && npm run build && npm run lint
```
Expected: 5 passed; build/lint green.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/ClassificationBlock.tsx frontend/src/components/__tests__/ClassificationBlock.test.tsx
git commit -m "feat(frontend): ClassificationBlock adds reporter_total + per-source rows"
```

---

### Task 5: `IpDetailPanel` (Z1 identity + 威胁明细 orchestration)

**Files:**
- Create: `frontend/src/components/IpDetailPanel.tsx`
- Create: `frontend/src/components/__tests__/IpDetailPanel.test.tsx`

**Interfaces:**
- Consumes: `LookupResult`, `MergedField` from `../api`; `confColor`, `confTextColor`, `ALGORITHM_ICONS` from `./threatDisplay`; `ClassificationBlock` from `./ClassificationBlock`.
- Produces: `IpDetailPanel({ r: LookupResult })` returning a `<div>` grid (the `<td>` wrapper stays in `ResultTable` for testability — see Task 6).

- [ ] **Step 1: Write the failing test `frontend/src/components/__tests__/IpDetailPanel.test.tsx`**

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { IpDetailPanel } from "../IpDetailPanel";
import type { LookupResult } from "../../api";

const mf = <T,>(value: T, confidence = 95) => ({
  value, confidence, algorithm: "cascade" as const,
  sources: [{ source: "geo", value, reliability: 0.9, authoritative: true }],
});

const r: LookupResult = {
  ip: "8.8.8.8",
  country: mf("US"),
  asn: mf(15169),
  as_name: mf("Google"),
  ip_range: mf("8.8.8.0/24"),
  is_isp: true,
  classifications: {
    c2_server: {
      type: "c2_server", verdict: "malicious", detected: true, confidence: 92,
      algorithm: "corroboration", corroborated: true, reporter_total: 3,
      verdict_conflict: false, malware_names: ["win.vidar"],
      details: [{ source: "otx", reliability: 0.9 }], sources: [],
    },
  },
  attributes: {},
  is_whitelisted: false,
  whitelist_notes: [],
};

describe("IpDetailPanel", () => {
  it("renders Z1 identity fields", () => {
    render(<IpDetailPanel r={r} />);
    expect(screen.getByText("国家")).toBeInTheDocument();
    expect(screen.getByText("US")).toBeInTheDocument();
    expect(screen.getByText("ASN")).toBeInTheDocument();
    expect(screen.getByText("机构 / ISP")).toBeInTheDocument();
    expect(screen.getByText("网段")).toBeInTheDocument();
  });

  it("renders the 威胁明细 section with the classification block", () => {
    render(<IpDetailPanel r={r} />);
    expect(screen.getByText("威胁明细")).toBeInTheDocument();
    expect(screen.getByText("C2")).toBeInTheDocument();
    expect(screen.getByText(/·3上报/)).toBeInTheDocument();
  });

  it("shows 未命中 when there are no classifications", () => {
    const clean = { ...r, classifications: {} };
    render(<IpDetailPanel r={clean} />);
    expect(screen.getByText("未命中")).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run, verify it fails**

```bash
cd frontend && npm test -- IpDetailPanel
```
Expected: FAIL — `Failed to resolve import "../IpDetailPanel"`.

- [ ] **Step 3: Create `frontend/src/components/IpDetailPanel.tsx`**

(`FieldDetail` is moved here verbatim from `ResultTable.tsx`; it is the Z1 identity row.)

```tsx
import type { LookupResult, MergedField } from "../api";
import { confColor, confTextColor, ALGORITHM_ICONS } from "./threatDisplay";
import { ClassificationBlock } from "./ClassificationBlock";

function FieldDetail<T>({
  label,
  field,
  format,
}: {
  label: string;
  field: MergedField<T>;
  format: (v: T) => string;
}) {
  const entries = field.sources;
  if (entries.length === 0) return null;
  return (
    <div>
      <div className="flex items-center gap-2 mb-1">
        <span className="text-xs font-medium text-zinc-300">{label}</span>
        <span className="text-[10px] text-zinc-500">{format(field.value)}</span>
        <span className={`inline-block h-1.5 w-1.5 rounded-full ${confColor(field.confidence)}`} />
        <span className={`text-[10px] ${confTextColor(field.confidence)}`}>{field.confidence}</span>
        <span className="text-[10px] text-zinc-600">{ALGORITHM_ICONS[field.algorithm] ?? field.algorithm}</span>
      </div>
      {entries.length > 0 && (
        <div className="ml-3 flex flex-wrap gap-x-4 gap-y-0.5">
          {entries.map((s) => (
            <span key={s.source} className="text-[11px]">
              <span className="text-zinc-500">{s.source}</span>
              {s.authoritative && (
                <span className="text-amber-400 ml-0.5" title="authoritative">★</span>
              )}
              <span className="text-zinc-700 mx-1">:</span>
              <span className="text-zinc-400">{format(s.value)}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

export function IpDetailPanel({ r }: { r: LookupResult }) {
  const classKeys = Object.keys(r.classifications);
  return (
    <div className="grid gap-2.5">
      <FieldDetail label="国家" field={r.country} format={String} />
      <FieldDetail label="ASN" field={r.asn} format={(v) => String(v)} />
      <FieldDetail label="机构 / ISP" field={r.as_name} format={String} />
      <div>
        <span className="text-xs font-medium text-zinc-300">威胁明细</span>
        {classKeys.length === 0 ? (
          <div className="ml-3 mt-1 text-[11px] text-zinc-600">未命中</div>
        ) : (
          <div className="ml-3 mt-1 space-y-2.5">
            {classKeys.map((type) => (
              <ClassificationBlock key={type} type={type} ca={r.classifications[type]} />
            ))}
          </div>
        )}
      </div>
      <FieldDetail label="网段" field={r.ip_range} format={String} />
    </div>
  );
}
```

- [ ] **Step 4: Run, verify it passes**

```bash
cd frontend && npm test -- IpDetailPanel && npm run build && npm run lint
```
Expected: 3 passed; build/lint green.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/IpDetailPanel.tsx frontend/src/components/__tests__/IpDetailPanel.test.tsx
git commit -m "feat(frontend): IpDetailPanel orchestrates Z1 identity + 威胁明细 (Z2-Z4)"
```

---

### Task 6: Wire `IpDetailPanel` into `ResultTable`; delete the old panel

**Files:**
- Modify: `frontend/src/components/ResultTable.tsx`

**Interfaces:**
- Consumes: `IpDetailPanel` from `./IpDetailPanel`.
- Produces: the expanded row renders `<IpDetailPanel>` inside the existing `<td colSpan={7}>`. `ResultTable.tsx` no longer defines `FieldDetail`, `ClassificationDetailPanel`, or `ExpandableDetail`.

- [ ] **Step 1: Delete the now-duplicated internals from `ResultTable.tsx`**

Remove these three components from `frontend/src/components/ResultTable.tsx` (their responsibilities moved to `IpDetailPanel`/`ClassificationBlock`/`SourceDetailRow` in Tasks 3–5):
- `FieldDetail` (the generic identity-row component — ~lines 236–276)
- `ClassificationDetailPanel` (~lines 278–346)
- `ExpandableDetail` (~lines 348–360)

Add the import alongside the existing `threatDisplay` import:
```ts
import { IpDetailPanel } from "./IpDetailPanel";
```

- [ ] **Step 2: Replace the expanded-row render site**

In `ResultTable`'s render, the expanded branch currently is:
```tsx
{expanded.has(r.ip) && (
  <motion.tr
    key={"detail-" + r.ip}
    initial={{ opacity: 0 }}
    animate={{ opacity: 1 }}
    exit={{ opacity: 0 }}
    transition={{ duration: 0.15 }}
  >
    <ExpandableDetail r={r} />
  </motion.tr>
)}
```
Change `<ExpandableDetail r={r} />` to:
```tsx
    <td colSpan={7} className="px-5 py-3 bg-zinc-900/60 border-b border-zinc-800/40">
      <IpDetailPanel r={r} />
    </td>
```
(`colSpan={7}` matches the 7 columns defined in `cols`. The wrapper classes are the exact ones `ExpandableDetail` used.)

- [ ] **Step 3: Verify the full suite + build + lint**

```bash
cd frontend && npm test && npm run build && npm run lint
```
Expected: all tests pass; build/lint green. (No `noUnusedLocals` errors — `FieldDetail`/`ClassificationDetailPanel`/`ExpandableDetail` are deleted, not orphaned; nothing else in `ResultTable` referenced them.)

- [ ] **Step 4: Browser smoke check**

```bash
cd frontend && npm run dev
```
Open the app, look up an IP that hits a threat source (e.g. one known to threatfox/otx). Expand the row. Confirm: Z1 identity renders as before; 威胁明细 shows the verdict/已印证/·N上报 header, aggregated malware chips, and per-source rows with reliability + (where present) comment/tags/reporters and the ▸ extra toggle. Confirm a clean IP shows 未命中 with no crash.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/ResultTable.tsx
git commit -m "refactor(frontend): wire IpDetailPanel into expanded row, drop old panel"
```

---

### Task 7: CSV export — 5 new aggregated columns

**Files:**
- Create: `frontend/src/components/csvExport.ts`
- Create: `frontend/src/components/__tests__/csvExport.test.ts`
- Modify: `frontend/src/components/ExportCsv.tsx`

**Interfaces:**
- Consumes: `LookupResult` from `../api`; `threatSummary` from `./threatDisplay`.
- Produces: `aggregateThreatDepth(r)` → `{ reporter_total, verdict_conflict, corroborated, malware_names, top_reliability }`; `buildCsv(results)` → full CSV string. `ExportCsv` calls `buildCsv` and triggers the download.

- [ ] **Step 1: Write the failing test `frontend/src/components/__tests__/csvExport.test.ts`**

```ts
import { describe, it, expect } from "vitest";
import { aggregateThreatDepth, buildCsv } from "../csvExport";
import type { LookupResult } from "../../api";

const mf = (value: string) => ({
  value, confidence: 95, algorithm: "cascade" as const,
  sources: [{ source: "geo", value, reliability: 0.9, authoritative: true }],
});

const r: LookupResult = {
  ip: "8.8.8.8", country: mf("US"), asn: mf("15169"), as_name: mf("Google"),
  ip_range: mf("8.8.8.0/24"), is_isp: true,
  classifications: {
    c2_server: {
      type: "c2_server", verdict: "malicious", detected: true, confidence: 92,
      algorithm: "corroboration", corroborated: true, reporter_total: 3,
      verdict_conflict: true, malware_names: ["win.vidar"],
      details: [
        { source: "otx", reliability: 0.9 },
        { source: "threatfox", reliability: 0.73 },
      ],
      sources: [],
    },
  },
  attributes: { is_proxy: [{ source: "ip2proxy", value: true, native_type: "PUB" }] },
  is_whitelisted: false, whitelist_notes: [],
};

describe("aggregateThreatDepth", () => {
  it("sums reporter_total, flags conflict/corroborated, unions malware", () => {
    const a = aggregateThreatDepth(r);
    expect(a.reporter_total).toBe(3);
    expect(a.verdict_conflict).toBe(true);
    expect(a.corroborated).toBe(true);
    expect(a.malware_names).toEqual(["win.vidar"]);
  });
  it("top_reliability = max reliability among the dominant-verdict details", () => {
    expect(aggregateThreatDepth(r).top_reliability).toBe(0.9);
  });
  it("clean IP yields zeros/empty", () => {
    const clean = { ...r, classifications: {} };
    const a = aggregateThreatDepth(clean);
    expect(a.reporter_total).toBe(0);
    expect(a.verdict_conflict).toBe(false);
    expect(a.corroborated).toBe(false);
    expect(a.malware_names).toEqual([]);
    expect(a.top_reliability).toBe(0);
  });
});

describe("buildCsv", () => {
  it("emits the header with the 5 new columns after threat_tags", () => {
    const csv = buildCsv([r]);
    const headerRow = csv.split("\n")[0];
    const tagsIdx = headerRow.split(",").indexOf("threat_tags");
    const afterTags = headerRow.split(",").slice(tagsIdx + 1, tagsIdx + 6);
    expect(afterTags).toEqual([
      "reporter_total", "verdict_conflict", "corroborated", "malware_names", "top_reliability",
    ]);
  });
  it("writes the aggregated values into the data row", () => {
    const row = buildCsv([r]).split("\n")[1];
    // reporter_total,verdict_conflict,corroborated sit right after threat_tags value
    expect(row).toContain(",3,True,True,win.vidar,0.9,");
  });
});
```

- [ ] **Step 2: Run, verify it fails**

```bash
cd frontend && npm test -- csvExport
```
Expected: FAIL — `Failed to resolve import "../csvExport"`.

- [ ] **Step 3: Create `frontend/src/components/csvExport.ts`**

```ts
import type { LookupResult } from "../api";
import { threatSummary, classLabel, familyShort } from "./threatDisplay";

export function aggregateThreatDepth(r: LookupResult) {
  const cas = Object.values(r.classifications);
  const reporter_total = cas.reduce((s, c) => s + (c.reporter_total || 0), 0);
  const verdict_conflict = cas.some((c) => c.verdict_conflict);
  const corroborated = cas.some((c) => c.corroborated);
  const mw = new Set<string>();
  for (const c of cas) for (const m of c.malware_names) mw.add(m);
  const malware_names = [...mw].sort();
  const dominant = threatSummary(r).verdict;
  let top_reliability = 0;
  for (const c of cas) {
    if (c.verdict === dominant) {
      for (const d of c.details) {
        if ((d.reliability ?? 0) > top_reliability) top_reliability = d.reliability;
      }
    }
  }
  return {
    reporter_total,
    verdict_conflict,
    corroborated,
    malware_names,
    top_reliability: Math.round(top_reliability * 100) / 100,
  };
}

const csvEscape = (v: string) => (/[,"\n\r]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);

function threatTags(r: LookupResult): string {
  const tags = Object.keys(r.classifications)
    .filter((t) => {
      const ca = r.classifications[t];
      return ca.detected && ca.confidence > 0;
    })
    .map((type) => {
      const ca = r.classifications[type];
      const label = classLabel(type);
      const family = ca.malware_names.length > 0 ? familyShort(ca.malware_names[0]) : null;
      return family ? `${label}·${family}` : label;
    });
  return tags.join(" | ");
}

function assetVal(r: LookupResult, key: string): string {
  const stmts = r.attributes?.[key];
  return stmts && stmts.length ? String(stmts[0].value) : "";
}

function assetNative(r: LookupResult, key: string): string {
  const stmts = r.attributes?.[key];
  return stmts && stmts.length ? stmts[0].native_type ?? "" : "";
}

export function buildCsv(results: LookupResult[]): string {
  const header =
    "ip,asn,asn_confidence,country,country_confidence,as_name,as_name_confidence," +
    "is_isp,verdict,verdict_confidence,threat_tags," +
    "reporter_total,verdict_conflict,corroborated,malware_names,top_reliability," +
    "ip_range,range_confidence,error," +
    "is_proxy,proxy_subtype,is_hosting,is_tor,is_vpn,carrier\n";

  const rows = results
    .map((r) => {
      const summary = threatSummary(r);
      const depth = aggregateThreatDepth(r);
      return [
        csvEscape(r.ip),
        csvEscape(String(r.asn.value)),
        String(r.asn.confidence),
        csvEscape(r.country.value),
        String(r.country.confidence),
        csvEscape(r.as_name.value),
        String(r.as_name.confidence),
        String(r.is_isp),
        csvEscape(summary.verdict),
        String(summary.confidence),
        csvEscape(threatTags(r)),
        String(depth.reporter_total),
        String(depth.verdict_conflict),
        String(depth.corroborated),
        csvEscape(depth.malware_names.join("|")),
        String(depth.top_reliability),
        csvEscape(r.ip_range.value),
        String(r.ip_range.confidence),
        csvEscape(r.error ?? ""),
        csvEscape(assetVal(r, "is_proxy")),
        csvEscape(assetNative(r, "is_proxy")),
        csvEscape(assetVal(r, "is_hosting")),
        csvEscape(assetVal(r, "is_tor")),
        csvEscape(assetVal(r, "is_vpn")),
        csvEscape(assetVal(r, "carrier")),
      ].join(",");
    })
    .join("\n");

  return header + rows;
}
```

- [ ] **Step 4: Run, verify it passes**

```bash
cd frontend && npm test -- csvExport
```
Expected: 5 passed.

- [ ] **Step 5: Slim `ExportCsv.tsx` to use `buildCsv`**

Replace the body of `frontend/src/components/ExportCsv.tsx` with:

```tsx
import { useMemo } from "react";
import type { LookupResult } from "../api";
import { buildCsv } from "./csvExport";

interface ExportCsvProps {
  results: LookupResult[];
}

export function ExportCsv({ results }: ExportCsvProps) {
  const disabled = results.length === 0;
  const csv = useMemo(() => (disabled ? "" : buildCsv(results)), [results, disabled]);

  const handleExport = () => {
    if (!csv) return;
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ip-lookup-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <button
      onClick={handleExport}
      disabled={disabled}
      className="rounded-lg bg-emerald-500 px-5 py-2 text-sm font-semibold text-zinc-950 transition-transform hover:scale-[1.02] active:scale-[0.98] disabled:opacity-40 disabled:cursor-not-allowed"
    >
      Export CSV ({results.length} rows)
    </button>
  );
}
```

- [ ] **Step 6: Run the full gate**

```bash
cd frontend && npm test && npm run build && npm run lint
```
Expected: all green. (The old per-file helpers `csvEscape`/`assetVal`/etc. now live in `csvExport.ts`; `ExportCsv.tsx` no longer defines them, so no duplicates.)

- [ ] **Step 7: Commit**

```bash
git add frontend/src/components/csvExport.ts frontend/src/components/__tests__/csvExport.test.ts frontend/src/components/ExportCsv.tsx
git commit -m "feat(frontend): CSV export gains reporter_total/conflict/corroborated/malware/top_reliability"
```

---

### Task 8: STIX verification + full browser verification

**Files:** none modified (verification-only). Edit only if STIX is found incomplete.

- [ ] **Step 1: Confirm STIX already surfaces the preserved fields (commit b89b0d6)**

```bash
git show b89b0d6 --stat
grep -nE "extra|details|malware_names|verdict_conflict" backend/ipdb/*stix*.py backend/main.py 2>/dev/null
```
Expected: the STIX builder wires `extra`/`details`/`malware_names`/`verdict_conflict` into an extension-definition. If yes → no STIX work (this task is verification only). If a preserved field is missing from the STIX output, stop and flag it — do not silently expand backend scope (spec defers backend changes; this is a detection step).

- [ ] **Step 2: Full browser golden-path + edge cases**

```bash
cd frontend && npm run dev
```
Walk these scenarios, confirming each:
1. **Malicious IP with full richness** (comment + tags + reporter_count + extra) — Z2 shows ·N上报; Z3 per-source rows show reliability, malware, comment (truncated+title), tags, reporters; ▸ extra toggles the JSON.
2. **`verdict_conflict` IP** — 判定冲突 badge in Z2; per-source rows reveal divergent verdicts (visible via the detail reliability/source list).
3. **Clean IP** (no classifications) — 威胁明细 shows 未命中; no empty zones; no crash.
4. **CSV export** — download and open; the 5 new columns are present after `threat_tags` and populated (reporter_total numeric, True/False booleans, malware pipe-joined, top_reliability 0–1).

- [ ] **Step 3: Final gate**

```bash
cd frontend && npm test && npm run build && npm run lint
```
Expected: all green. If everything passes and STIX was already complete, no commit is needed for this task — it is verification. If a code fix was required, commit it with an appropriate message.

---

## Self-Review (completed during authoring)

- **Spec coverage:** Z2 reporter_total → Task 4; Z3 reliability/malware/comment/tags/reporter/full-extra → Task 3; Z4 extra toggle → Task 3; Z1 unchanged → Task 5 (FieldDetail moved verbatim); CSV 5 columns → Task 7; deferred items (isp/asset-extra/last_seen) → explicitly excluded in Global Constraints; STIX verify → Task 8. UI component-extraction architecture → Tasks 2–6. ✓
- **Placeholder scan:** no TBD/TODO/"add error handling". Every code step contains full source. ✓
- **Type consistency:** `ClassificationDetail`, `ClassificationAssessment`, `MergedField`, `LookupResult` field names match `api.ts` exactly (`reporter_total`, `verdict_conflict`, `corroborated`, `malware_names`, `details`, `reliability`, `native_confidence`, `first_seen`, `extra.native_type`). Shared helper names (`threatSummary`, `classLabel`, `familyShort`, `confTextColor`, `confColor`, `VERDICT_*`, `ALGORITHM_ICONS`, `normType`) are identical across `threatDisplay.ts`, the tests, and the consumers. ✓
