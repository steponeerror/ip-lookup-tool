import { Routes, Route } from "react-router-dom";
import Layout from "./Layout";
import LookupView from "./LookupView";
import SourcesPage from "./pages/SourcesPage";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<LookupView />} />
        <Route path="sources" element={<SourcesPage />} />
      </Route>
    </Routes>
  );
}
