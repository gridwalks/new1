import SafeMarkdown from "./SafeMarkdown";
export default function ChatMessage({ role, content }: { role: "user" | "assistant"; content: string }){
  const side = role === "user" ? "items-end" : "items-start";
  const bubble = role === "user" ? "bg-blue-600 text-white" : "bg-neutral-900 border border-neutral-800 text-neutral-100";
  return (
    <div className={`w-full flex ${side}`}>
      <div className={`max-w-2xl rounded-2xl px-4 py-3 ${bubble}`}>
        <SafeMarkdown markdown={content} />
      </div>
    </div>
  );
}
