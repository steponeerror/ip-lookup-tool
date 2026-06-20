import { Routes, Route } from "react-router-dom";
import Layout from "./Layout";
import LookupView from "./LookupView";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<LookupView />} />
        <Route path="sources" element={<div className="text-sm text-zinc-500">Sources page</div>} />
      </Route>
    </Routes>
  );
}
