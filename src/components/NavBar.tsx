import { Link, useLocation } from "react-router-dom";
import { isAdmin } from "../lib/api";
import React from "react";
export default function NavBar(){
  const [user, setUser] = React.useState<any | null>(null);
  const loc = useLocation();
  React.useEffect(() => {
    const id: any = (window as any).netlifyIdentity;
    if (!id) return;
    setUser(id.currentUser());
    id.on("login", (u: any) => setUser(u));
    id.on("logout", () => setUser(null));
  }, []);
  const active = (p: string) => loc.pathname === p ? "text-white" : "text-neutral-300 hover:text-white";
  const admin = isAdmin(user);
  return (
    <nav className="border-b border-neutral-800 bg-neutral-950 sticky top-0 z-10">
      <div className="mx-auto max-w-6xl px-4 py-3 flex items-center gap-4">
        <Link to="/" className="text-xl font-bold">AcceleraQA</Link>
        <Link to="/app" className={active("/app")}>Chat</Link>
        <Link to="/notebook" className={active("/notebook")}>Notebook</Link>
        {admin && (<div className="ml-2 flex items-center gap-3">
          <span className="text-neutral-500 text-sm">Admin:</span>
          <Link to="/admin/sys" className={active("/admin/sys")}>System</Link>
          <Link to="/admin/rag" className={active("/admin/rag")}>RAG</Link>
          <Link to="/admin/logs" className={active("/admin/logs")}>Logs</Link>
        </div>)}
        <div className="ml-auto flex items-center gap-3">
          {user ? (<>
            <span className="text-sm text-neutral-400">{user.email}</span>
            <button onClick={() => (window as any).netlifyIdentity?.logout()}>Logout</button>
          </>) : (<button onClick={() => (window as any).netlifyIdentity?.open("login")}>Login</button>)}
        </div>
      </div>
    </nav>
  );
}
