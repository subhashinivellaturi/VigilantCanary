import React, { useState } from 'react';
import { SecurityCard } from './SecurityCard';
import { useToast } from '../ui/Toast';

interface ChatMessage {
  id: string;
  who: 'user' | 'assistant';
  text: string;
}

/**
 * SecurityAssistant - simple chat interface
 */
export const SecurityAssistant: React.FC = () => {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const { showToast } = useToast();

  const send = () => {
    if (!input.trim()) return showToast('Please enter a message', 'error');
    const msg: ChatMessage = { id: String(Date.now()), who: 'user', text: input.trim() };
    setMessages((s) => [...s, msg]);
    setInput('');

    // fake assistant reply
    setTimeout(() => {
      setMessages((s) => [...s, { id: String(Date.now() + 1), who: 'assistant', text: `Simulated response to: ${msg.text}` }]);
    }, 500);
  };

  return (
    <SecurityCard title="AI Security Assistant" subtitle="Ask for remediation suggestions or analysis">
      <div className="flex flex-col gap-3">
        <div className="max-h-48 overflow-auto p-2 space-y-2">
          {messages.length === 0 ? (
            <div className="text-slate-400 text-sm">No messages yet. Try asking about recent scans.</div>
          ) : (
            messages.map((m) => (
              <div key={m.id} className={`p-2 rounded ${m.who === 'user' ? 'bg-slate-800 self-end' : 'bg-slate-700 self-start'}`}>
                <div className="text-sm">{m.text}</div>
              </div>
            ))
          )}
        </div>

        <div className="flex gap-2">
          <input value={input} onChange={(e) => setInput(e.target.value)} placeholder="Ask the assistant..." className="flex-1 p-2 rounded-md bg-slate-800 border border-slate-700" />
          <button onClick={send} className="px-4 py-2 rounded-md bg-emerald-600 hover:bg-emerald-500 text-white">Send</button>
        </div>
      </div>
    </SecurityCard>
  );
};
