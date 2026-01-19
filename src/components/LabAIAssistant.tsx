import { useState, useRef, useEffect } from 'react';
import { Send, MessageCircle } from 'lucide-react';

interface LabAIAssistantProps {
  vulnerabilityType: string;
}

export function LabAIAssistant({ vulnerabilityType }: LabAIAssistantProps) {
  const [messages, setMessages] = useState<Array<{ role: 'assistant' | 'user'; content: string }>>([
    {
      role: 'assistant',
      content: getInitialMessage(vulnerabilityType),
    },
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  function getInitialMessage(vulnType: string): string {
    const messages: Record<string, string> = {
      'sql-injection':
        "SQL Injection Assistant!\n\nQuick payloads:\n• ' OR '1'='1\n• admin'--\n• ' OR 1=1--\n\nThe -- comments out everything after it. Try these in the search box!",
      'xss':
        "XSS Exploitation Guide!\n\nTry these:\n• <script>alert('XSS')</script>\n• <img src=x onerror=alert(1)>\n• <svg onload=alert('XSS')>\n\nJavaScript executes in your browser!",
      'html-injection':
        "HTML Injection Assistant!\n\nTry injecting:\n• <h1 style=\"color:red\">HACKED</h1>\n• <marquee>Text</marquee>\n• <iframe src=\"url\"></iframe>\n\nInject any HTML to modify the page!",
      'auth-bypass':
        "Auth Bypass Guide!\n\nMethods:\n• SQL Injection: admin'--\n• Default creds: admin/admin\n• Boolean: ' OR '1'='1\n\nPassword check gets bypassed!",
      'broken-access':
        "IDOR Assistant!\n\nWhat's happening:\n• View any user's data\n• No authorization checks\n• Click different user IDs\n• Access sensitive info!",
      'csrf':
        "CSRF Guide!\n\nKey concept:\n• No CSRF tokens = vulnerable\n• Attackers forge requests\n• Your session is used\n• Actions execute as you!\n\nCheck the example code!",
    };
    return messages[vulnType] || "Hello! I'm your lab assistant. Ask me about this vulnerability!";
  }

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;

    const userMessage = input.trim();
    setInput('');
    setMessages((prev) => [...prev, { role: 'user', content: userMessage }]);
    setIsLoading(true);

    setTimeout(() => {
      const response = getLabResponse(vulnerabilityType, userMessage);
      setMessages((prev) => [...prev, { role: 'assistant', content: response }]);
      setIsLoading(false);
    }, 600);
  };

  function getLabResponse(vulnType: string, question: string): string {
    const lowerQ = question.toLowerCase();

    if (lowerQ.includes('what') || lowerQ.includes('how')) {
      const tips: Record<string, string> = {
        'sql-injection':
          "SQL Injection steps:\n\n1. Find vulnerable input (search/login)\n2. Try ' to break query\n3. Use OR: ' OR '1'='1\n4. Comment out rest: ' OR '1'='1'--\n5. Extract data with UNION\n\nPayload: ' OR '1'='1'--\n\nTry it!",
        'xss':
          "XSS exploitation:\n\n1. Find where input is reflected\n2. Try: <script>alert('XSS')</script>\n3. If blocked, try: <img onerror=alert(1)>\n4. Use encoding if filtered\n5. Check if sanitized\n\nStart simple!",
        'html-injection':
          "HTML Injection steps:\n\n1. Find input that renders HTML\n2. Try: <h1>Test</h1>\n3. Inject styling: <h1 style=\"color:red\">Hacked</h1>\n4. Try <iframe> or <marquee>\n5. Deface or trick users\n\nGive it a shot!",
        'auth-bypass':
          "Auth bypass methods:\n\n1. Default creds: admin/admin\n2. SQL injection: admin'--\n3. Boolean: ' OR '1'='1\n4. Password reset flaws\n5. Session manipulation\n\nWhich to try?",
        'broken-access':
          "Test access control:\n\n1. Login as user\n2. Click different User IDs\n3. Change IDs: 1, 2, 3...\n4. Notice no auth checks\n5. Access any user's data\n\nThis is IDOR!",
        'csrf':
          "CSRF exploitation:\n\n1. Understand vulnerable action\n2. Create malicious form\n3. Host on external site\n4. Trick user to visit\n5. Action executes with their auth\n\nCheck the example code!",
      };
      return tips[vulnType] || "I can help with this vulnerability!";
    }

    if (lowerQ.includes('why') || lowerQ.includes('dangerous')) {
      return "This is dangerous because:\n\n• Unauthorized access granted\n• Data stolen or modified\n• System compromise possible\n• User trust violated\n• Legal/compliance issues\n\nAlways practice ethically!";
    }

    if (lowerQ.includes('payload')) {
      const payloads: Record<string, string> = {
        'sql-injection': "Payloads:\n\nBasic: ' OR '1'='1\nComment: admin'--\nUnion: ' UNION SELECT * FROM users--\nBoolean: ' AND 1=1--\nTime: ' AND SLEEP(5)--",
        'xss': "XSS Payloads:\n\n<script>alert('XSS')</script>\n<img src=x onerror=alert(1)>\n<svg onload=alert('XSS')>\n<body onload=alert(1)>\n<iframe src=javascript:alert(1)>",
        'html-injection': "HTML Payloads:\n\n<h1>HACKED</h1>\n<marquee>Scrolling!</marquee>\n<iframe src=\"url\"></iframe>\n<img src=\"url\">\n<div style=\"...\">Content</div>",
        'auth-bypass': "Auth Payloads:\n\nadmin'--\n' OR '1'='1'--\nadmin'#\n' OR 1=1--\nDefault: admin/admin",
      };
      return payloads[vulnType] || "Try the payloads in the instructions!";
    }

    if (lowerQ.includes('stuck') || lowerQ.includes('help') || lowerQ.includes('hint')) {
      return "Hints:\n\n1. Read the instructions carefully\n2. Copy the quick payload\n3. Paste it in the input field\n4. Watch for success message\n5. Try variations\n\nYou got this!";
    }

    return "Great question!\n\n• Try the quick payload first\n• Follow step-by-step instructions\n• Check for error messages\n• Use DevTools (F12) to inspect\n• Experiment safely\n\nWhat's your specific challenge?";
  }

  return (
    <div className="bg-white rounded-lg shadow-lg overflow-hidden flex flex-col h-96 border-l-4 border-emerald-500">
      <div className="bg-gradient-to-r from-emerald-600 to-teal-600 text-white p-4">
        <div className="flex items-center space-x-2">
          <MessageCircle className="h-5 w-5" />
          <span className="font-semibold">Lab AI Assistant</span>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-3 bg-gray-50">
        {messages.map((msg, idx) => (
          <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            <div
              className={`max-w-xs px-4 py-2 rounded-lg text-sm ${
                msg.role === 'user'
                  ? 'bg-emerald-600 text-white rounded-br-none'
                  : 'bg-white text-gray-900 border border-gray-200 rounded-bl-none'
              }`}
            >
              <p className="whitespace-pre-line">{msg.content}</p>
            </div>
          </div>
        ))}
        {isLoading && (
          <div className="flex justify-start">
            <div className="bg-white text-gray-900 border border-gray-200 px-4 py-2 rounded-lg rounded-bl-none text-sm">
              <div className="flex space-x-1">
                <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce"></div>
                <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0.1s' }}></div>
                <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
              </div>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      <div className="border-t border-gray-200 p-3 bg-white">
        <div className="flex space-x-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleSend()}
            placeholder="Ask for hints..."
            className="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-emerald-500 focus:border-transparent text-sm"
            disabled={isLoading}
          />
          <button
            onClick={handleSend}
            disabled={!input.trim() || isLoading}
            className="px-3 py-2 bg-emerald-600 text-white rounded-lg hover:bg-emerald-700 disabled:bg-gray-400 transition-colors"
          >
            <Send className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
