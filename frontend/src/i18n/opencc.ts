// Lazy-loaded simplified→traditional Chinese converter (opencc-js).
// The dictionary is dynamically imported only when zh-TW is first selected,
// so it lands in a separate Vite chunk and stays out of the main bundle.
let converter: ((s: string) => string) | null = null;
let loadPromise: Promise<void> | null = null;
const cache = new Map<string, string>();

export async function ensureOpenCC(): Promise<void> {
  if (converter) return;
  if (!loadPromise) {
    loadPromise = (async () => {
      const mod = await import("opencc-js");
      converter = mod.Converter({ from: "cn", to: "tw" });
    })();
  }
  return loadPromise;
}

export function toTraditional(s: string): string {
  if (!converter) return s; // not ready yet — caller re-renders after ensureOpenCC resolves
  const hit = cache.get(s);
  if (hit !== undefined) return hit;
  const out = converter(s);
  cache.set(s, out);
  return out;
}
