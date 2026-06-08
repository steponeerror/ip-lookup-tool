import { useCallback, useState } from "react";

interface FileUploadProps {
  onUpload: (file: File) => void;
  loading: boolean;
}

export function FileUpload({ onUpload, loading }: FileUploadProps) {
  const [dragOver, setDragOver] = useState(false);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const file = e.dataTransfer.files[0];
      if (!file) return;
      const validExtensions = [".txt", ".csv"];
      const ext = file.name.substring(file.name.lastIndexOf(".")).toLowerCase();
      if (!validExtensions.includes(ext)) {
        alert("Please drop a .txt or .csv file");
        return;
      }
      if (file.size > 50 * 1024 * 1024) {
        alert("File exceeds 50MB limit");
        return;
      }
      onUpload(file);
    },
    [onUpload]
  );

  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) onUpload(file);
    },
    [onUpload]
  );

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
      onDragLeave={() => setDragOver(false)}
      onDrop={handleDrop}
      className={`flex flex-col items-center justify-center gap-3 rounded-lg border-2 border-dashed p-10 transition-colors ${
        dragOver
          ? "border-emerald-500 bg-emerald-500/5"
          : "border-zinc-800 bg-zinc-900"
      }`}
    >
      <p className="text-sm text-zinc-400">
        Drag and drop a <code className="text-emerald-400">.txt</code> or{" "}
        <code className="text-emerald-400">.csv</code> file
      </p>
      <label className="cursor-pointer rounded-lg bg-emerald-500 px-5 py-2 text-sm font-semibold text-zinc-950 transition-transform hover:scale-[1.02] active:scale-[0.98]">
        {loading ? "Uploading..." : "Choose File"}
        <input
          type="file"
          accept=".txt,.csv"
          onChange={handleChange}
          className="hidden"
          disabled={loading}
        />
      </label>
    </div>
  );
}
