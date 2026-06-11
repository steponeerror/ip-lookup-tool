interface IpInputProps {
  onQuery: (ips: string[]) => void;
  loading: boolean;
  progress?: { done: number; total: number; phase: string } | null;
}

export function IpInput({ onQuery, loading, progress }: IpInputProps) {
  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    const textarea = form.elements.namedItem("ips") as HTMLTextAreaElement;
    const ips = textarea.value
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);
    if (ips.length === 0) return;
    onQuery(ips);
  };

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-3">
      <label htmlFor="ips" className="text-sm font-medium text-zinc-400">
        IP Addresses
      </label>
      <textarea
        id="ips"
        name="ips"
        rows={10}
        placeholder={"1.1.1.1\n8.8.8.8\n114.114.114.114"}
        className="w-full rounded-lg border border-zinc-800 bg-zinc-900 p-3 font-mono text-sm text-zinc-100 placeholder:text-zinc-600 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 resize-none"
        disabled={loading}
      />
      <button
        type="submit"
        disabled={loading}
        className="relative self-end overflow-hidden rounded-lg bg-emerald-500 px-5 py-2 text-sm font-semibold text-zinc-950 transition-transform hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50 disabled:pointer-events-none"
      >
        {loading && (
          <span className="absolute inset-x-0 bottom-0 h-0.5">
            <span className="block h-full w-1/3 animate-[shimmer_1.5s_ease-in-out_infinite] rounded-full bg-emerald-300/60" />
          </span>
        )}
        {loading
          ? progress
            ? `${progress.done.toLocaleString()} / ${progress.total.toLocaleString()}`
            : "Querying..."
          : "Query"}
      </button>
    </form>
  );
}
