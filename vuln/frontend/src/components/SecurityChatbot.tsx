import { useState, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: Date;
}

interface ChatbotProps {
  systemPrompt?: string;
}

export function SecurityChatbot({ systemPrompt = "You are a friendly and educational Web Application Security Assistant. Provide short, actionable guidance and prioritize fixes by severity." }: ChatbotProps) {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: "0",
      role: "assistant",
      content: "Hello! I'm your security assistant. Ask me anything about vulnerabilities, remediation, or attack detection. I have knowledge of SQL Injection, Path Traversal, XSS, and Command Injection attacks.",
      timestamp: new Date(),
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    if (messagesEndRef.current && typeof (messagesEndRef.current as any).scrollIntoView === 'function') {
      messagesEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;

    const userMessage: Message = {
      id: Date.now().toString(),
      role: "user",
      content: input,
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput("");
    setLoading(true);

    try {
      // Simulate AI response using the system prompt as context
      const response = await simulateAIResponse(input, systemPrompt);

      const assistantMessage: Message = {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: response,
        timestamp: new Date(),
      };

      setMessages((prev) => [...prev, assistantMessage]);
    } catch (error) {
      const errorMessage: Message = {
        id: (Date.now() + 2).toString(),
        role: "assistant",
        content:
          "Sorry, I encountered an error. Please try again. Make sure the backend is running.",
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev, errorMessage]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <motion.div
      className="chatbot-container"
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: 0.5 }}
    >
      <div className="chatbot-header">
        <h3>🤖 Security Assistant</h3>
        <span className="status-indicator">Online</span>
      </div>

      <div className="chatbot-messages">
        <AnimatePresence>
          {messages.map((message) => (
            <motion.div
              key={message.id}
              className={`message ${message.role}`}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
            >
              <div className="message-content">
                <p>{message.content}</p>
                <span className="timestamp">
                  {message.timestamp.toLocaleTimeString()}
                </span>
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
        {loading && (
          <motion.div
            className="message assistant loading"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
          >
            <div className="typing-indicator">
              <span></span>
              <span></span>
              <span></span>
            </div>
          </motion.div>
        )}
        <div ref={messagesEndRef} />
      </div>

      <form onSubmit={handleSendMessage} className="chatbot-input-form">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask about vulnerabilities, fixes, best practices..."
          disabled={loading}
          className="chatbot-input"
        />
        <button
          type="submit"
          disabled={loading || !input.trim()}
          className="send-button"
        >
          {loading ? "..." : "Send"}
        </button>
      </form>
    </motion.div>
  );
}

// Simulate AI response based on keywords in the user message
async function simulateAIResponse(
  userMessage: string,
  _systemPrompt: string
): Promise<string> {
  const lower = userMessage.toLowerCase();

  // Simulate API delay
  await new Promise((resolve) => setTimeout(resolve, 800));

  if (lower.includes("xss")) {
    return (
      "XSS (Cross-Site Scripting) occurs when user input is rendered in HTML/JavaScript without proper escaping. " +
      "Attackers inject malicious scripts that execute in users' browsers. To fix: use textContent instead of innerHTML, " +
      "escape HTML entities, or use templating engines with autoescape enabled."
    );
  }

  if (lower.includes("command") || lower.includes("injection")) {
    return (
      "Command Injection happens when user input is passed to shell commands without proper escaping. " +
      "Use subprocess.run() with a list of arguments (no shell=True) in Python, or execFile/spawn in Node.js. " +
      "Never pass user input directly to shell=True or shell execution functions."
    );
  }

  if (lower.includes("sql")) {
    return (
      "SQL Injection occurs when user input is concatenated into SQL queries. " +
      "Always use parameterized queries (prepared statements) instead. In Python use ? or %s placeholders, " +
      "in JavaScript use ? placeholders with prepared statements, or use an ORM like Sequelize."
    );
  }

  if (lower.includes("path") || lower.includes("traversal")) {
    return (
      "Path Traversal vulnerabilities allow attackers to access files outside the intended directory using ../ sequences. " +
      "Validate and normalize file paths using Path.resolve() (Node.js) or pathlib (Python). " +
      "Always ensure the final path is within the allowed base directory."
    );
  }

  if (lower.includes("remediate") || lower.includes("fix")) {
    return (
      "To remediate vulnerabilities: 1) Identify the vulnerability type, 2) Use parameterized queries for SQL, " +
      "3) Escape output for XSS, 4) Use subprocess/execFile for command injection, 5) Validate file paths for traversal. " +
      "Use the Remediation button in the dashboard to get specific code fixes."
    );
  }

  if (lower.includes("best practice") || lower.includes("prevent")) {
    return (
      "Best practices: Use input validation and output encoding, employ parameterized queries, " +
      "use security headers (CSP), keep dependencies updated, implement HTTPS, use WAF (Web Application Firewall), " +
      "conduct regular security testing, and follow OWASP guidelines."
    );
  }

  return (
    "I can help with SQL Injection, Path Traversal, XSS, and Command Injection attacks. " +
    "Ask me about how to detect them, remediate vulnerabilities, or follow best practices. " +
    "You can also use the dashboard buttons to run live attack detection tests."
  );
}
