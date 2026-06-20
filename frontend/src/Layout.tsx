import { NavLink, Outlet } from "react-router-dom";
import { DbStatusBar } from "./components/DbStatusBar";

export default function Layout() {
  const linkClass = ({ isActive }: { isActive: boolean }) =>
    `rounded-md px-4 py-2 text-sm font-medium transition-colors ${
      isActive ? "bg-zinc-800 text-emerald-400" : "text-zinc-500 hover:text-zinc-300"
    }`;

  return (
    <div className="dot-grid min-h-screen pb-14">
      <div className="mx-auto max-w-7xl px-4 py-8 lg:px-8">
        <header className="mb-8">
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100">
            IP Lookup Tool
          </h1>
          <p className="mt-1 text-sm text-zinc-500">
            Batch IP to ASN lookup for threat analysis
          </p>
          <nav className="mt-4">
            <div className="flex gap-1 rounded-lg bg-zinc-900 p-1 sm:inline-flex">
              <NavLink to="/" end className={linkClass}>Lookup</NavLink>
              <NavLink to="/sources" className={linkClass}>Sources</NavLink>
            </div>
          </nav>
        </header>
        <Outlet />
      </div>
      <DbStatusBar />
    </div>
  );
}
