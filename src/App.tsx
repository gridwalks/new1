import { Routes, Route } from "react-router-dom";
import Landing from "./pages/Landing";
import ChatApp from "./pages/ChatApp";
import Notebook from "./pages/Notebook";
import AdminSys from "./pages/AdminSys";
import AdminRag from "./pages/AdminRag";
import AdminLogs from "./pages/AdminLogs";
import NavBar from "./components/NavBar";
export default function App(){
  return (<div><NavBar /><Routes>
    <Route path="/" element={<Landing/>} />
    <Route path="/app" element={<ChatApp/>} />
    <Route path="/notebook" element={<Notebook/>} />
    <Route path="/admin/sys" element={<AdminSys/>} />
    <Route path="/admin/rag" element={<AdminRag/>} />
    <Route path="/admin/logs" element={<AdminLogs/>} />
  </Routes></div>);
}
