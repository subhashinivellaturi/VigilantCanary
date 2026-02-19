import React, { useState, useRef, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { X, Send, Sparkles, Zap } from 'lucide-react';
import './AIAssistant.css';

interface Message {
  id: string;
  type: 'user' | 'assistant';
  text: string;
  timestamp: Date;
}

interface AIAssistantProps {
  isFullPage?: boolean;
}

export function AIAssistant({ isFullPage: isFullPageProp = false }: AIAssistantProps) {
  const location = useLocation();
  const isFullPage = location.pathname === '/ai-assistant' || isFullPageProp;
  const [isOpen, setIsOpen] = useState(isFullPage);
  const [messages, setMessages] = useState<Message[]>([
    {
      id: '1',
      type: 'assistant',
      text: 'Hey! I\'m your AI Security Assistant. I can help you with vulnerability analysis, understanding scan results, setting up scans, and learning about security best practices. What would you like to know?',
      timestamp: new Date(),
    },
  ]);
  const [inputValue, setInputValue] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Sample AI responses based on user input
  const aiResponses: { [key: string]: string[] } = {
    'vulnerability': [
      'Vulnerabilities are weaknesses in software that can be exploited. Common types include SQL Injection, Cross-Site Scripting (XSS), and Path Traversal. Would you like to learn more about any specific vulnerability type?',
      'A vulnerability is a flaw in the software security that attackers can exploit. The Vigilant Canary platform helps you identify these issues in your applications.',
    ],
    'scan': [
      'I can help you understand our scanning capabilities! We offer Vulnerability Scans, Port Scans, and Subdomain Enumeration. Which would you like to learn more about?',
      'A security scan analyzes your target for known vulnerabilities and misconfigurations. You can view all your past scans in the Scan History section.',
    ],
    'payload': [
      'A payload is a string of data sent to test for vulnerabilities. For example, "OR 1=1" tests for SQL Injection vulnerabilities. In our Vulnerability Analysis tool, you can test payloads against your target URL.',
      'Payloads are crafted inputs designed to trigger specific vulnerabilities. Common payloads test for injection flaws, XSS, and other security issues.',
    ],
    'remediation': [
      'Remediation involves fixing identified vulnerabilities. Common remediation steps include: using parameterized queries, implementing input validation, enabling security headers, and applying security patches. The platform provides specific remediation guidance for each vulnerability.',
      'After finding a vulnerability, remediation is the process of fixing it. Our analysis tool provides detailed remediation steps for each detected issue.',
    ],
    'xss': [
      'XSS (Cross-Site Scripting) is when an attacker injects malicious scripts into a web page. Remediation includes: output encoding, using Content Security Policy (CSP), and avoiding dangerous functions like innerHTML with user input.',
      'Cross-Site Scripting attacks happen when user input is not properly sanitized. Use textContent instead of innerHTML, implement CSP headers, and validate all inputs.',
    ],
    'sql': [
      'SQL Injection occurs when attackers manipulate SQL queries through user input. Prevention: use parameterized queries, apply input validation, and follow the principle of least privilege for database accounts.',
      'SQL Injection is a critical vulnerability where malicious SQL code is injected into queries. Always use prepared statements and parameterized queries to prevent this.',
    ],
    'anomaly': [
      'The Anomaly Score (0-100) indicates how suspicious a payload is based on ML models (Isolation Forest or LightGBM). Higher scores indicate higher risk. Scores are calculated by analyzing payload characteristics.',
      'Anomaly detection uses machine learning to identify unusual patterns. Our system analyzes special characters, SQL keywords, and other payload features.',
    ],
    'default': [
      'That\'s a great question! Could you be more specific? I can help with: vulnerability types, scanning methods, payload analysis, remediation steps, or platform features.',
      'I\'m here to help! You can ask me about vulnerabilities, scans, payloads, remediation, or how to use the Vigilant Canary platform.',
      'Great question! I can provide more details if you ask more specifically about vulnerabilities, scans, or security concepts.',
    ],
  };

  const getAIResponse = (userInput: string): string => {
    const lowerInput = userInput.toLowerCase();
    
    for (const [keyword, responses] of Object.entries(aiResponses)) {
      if (keyword !== 'default' && lowerInput.includes(keyword)) {
        return responses[Math.floor(Math.random() * responses.length)];
      }
    }
    
    return aiResponses['default'][Math.floor(Math.random() * aiResponses['default'].length)];
  };

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputValue.trim()) return;

    // Add user message
    const userMessage: Message = {
      id: Date.now().toString(),
      type: 'user',
      text: inputValue,
      timestamp: new Date(),
    };
    setMessages((prev) => [...prev, userMessage]);
    setInputValue('');
    setIsLoading(true);

    // Simulate AI response with context-aware answers
    setTimeout(() => {
      const responseText = getAIResponse(inputValue);

      const assistantMessage: Message = {
        id: (Date.now() + 1).toString(),
        type: 'assistant',
        text: responseText,
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev, assistantMessage]);
      setIsLoading(false);
    }, 1000);
  };

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // If full page view
  if (isFullPage) {
    return (
      <div className="ai-assistant-fullpage">
        <div className="ai-assistant-container full">
          {/* Header */}
          <div className="ai-assistant-header">
            <div className="ai-assistant-title">
              <Zap size={24} />
              <div>
                <h1>AI Security Assistant</h1>
                <p>Ask questions about vulnerabilities, scanning, and remediation</p>
              </div>
            </div>
          </div>

          {/* Messages */}
          <div className="ai-messages-container full">
            {messages.map((msg) => (
              <div
                key={msg.id}
                className={`ai-message ai-message--${msg.type}`}
              >
                {msg.type === 'assistant' && <Zap size={16} className="ai-message-icon" />}
                <div className="ai-message-bubble">
                  <div className="ai-message-content">
                    {msg.text}
                  </div>
                  <div className="ai-message-time">
                    {msg.timestamp.toLocaleTimeString([], {
                      hour: '2-digit',
                      minute: '2-digit',
                    })}
                  </div>
                </div>
              </div>
            ))}
            {isLoading && (
              <div className="ai-message ai-message--assistant">
                <Zap size={16} className="ai-message-icon" />
                <div className="ai-message-bubble">
                  <div className="ai-typing-indicator">
                    <span></span>
                    <span></span>
                    <span></span>
                  </div>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Input */}
          <form onSubmit={handleSendMessage} className="ai-input-form full">
            <input
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder="Ask me about vulnerabilities, scans, payloads, remediation..."
              className="ai-input"
              disabled={isLoading}
              autoFocus
            />
            <button
              type="submit"
              className="ai-send-btn"
              disabled={!inputValue.trim() || isLoading}
              title="Send message"
            >
              <Send size={20} />
            </button>
          </form>
        </div>
      </div>
    );
  }

  // Floating button view (original behavior)
  return (
    <>
      {/* Floating Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="ai-assistant-button"
        title="Open AI Assistant"
        aria-label="Open AI Assistant Chat"
      >
        {isOpen ? <X size={24} /> : <Sparkles size={24} />}
      </button>

      {/* Chat Panel */}
      {isOpen && (
        <div className="ai-assistant-panel">
          {/* Header */}
          <div className="ai-assistant-header">
            <div className="ai-assistant-title">
              <Sparkles size={18} />
              AI Security Assistant
            </div>
            <button
              onClick={() => setIsOpen(false)}
              className="ai-close-btn"
              aria-label="Close chat"
            >
              <X size={20} />
            </button>
          </div>

          {/* Messages */}
          <div className="ai-messages-container">
            {messages.map((msg) => (
              <div
                key={msg.id}
                className={`ai-message ai-message--${msg.type}`}
              >
                <div className="ai-message-content">
                  {msg.text}
                </div>
                <div className="ai-message-time">
                  {msg.timestamp.toLocaleTimeString([], {
                    hour: '2-digit',
                    minute: '2-digit',
                  })}
                </div>
              </div>
            ))}
            {isLoading && (
              <div className="ai-message ai-message--assistant">
                <div className="ai-typing-indicator">
                  <span></span>
                  <span></span>
                  <span></span>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Input */}
          <form onSubmit={handleSendMessage} className="ai-input-form">
            <input
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder="Ask me anything..."
              className="ai-input"
              disabled={isLoading}
            />
            <button
              type="submit"
              className="ai-send-btn"
              disabled={!inputValue.trim() || isLoading}
              title="Send message"
            >
              <Send size={18} />
            </button>
          </form>
        </div>
      )}
    </>
  );
}

export default AIAssistant;
