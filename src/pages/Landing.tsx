export default function Landing(){
  return (
    <div className="mx-auto max-w-4xl px-4 py-12">
      <h1 className="text-4xl font-bold mb-4">AcceleraQA</h1>
      <p className="text-neutral-300 mb-6">An AI learning assistant for pharmaceutical Quality & Compliance.</p>
      <ul className="list-disc list-inside text-neutral-300 space-y-2">
        <li>Concise answers with curated “Further learning” resources.</li>
        <li>Admin can update the system prompt, manage RAG docs, and view logs.</li>
        <li>Netlify Identity authentication (admin role or allowlist).</li>
      </ul>
      <div className="mt-8"><a href="/app" className="px-4 py-3 bg-blue-600 rounded-lg">Open the app</a></div>
    </div>
  );
}
