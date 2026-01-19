import { useState, useRef, useEffect } from 'react';
import { Send, Bot, User, Loader } from 'lucide-react';

interface Message {
  role: 'user' | 'assistant';
  content: string;
}

export function AIAssistant() {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content: 'Hello! I\'m your cybersecurity learning assistant. Ask me anything about vulnerabilities, security tools, or ethical hacking techniques!',
    },
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;

    const userMessage = input.trim();
    setInput('');
    setMessages(prev => [...prev, { role: 'user', content: userMessage }]);
    setIsLoading(true);

    try {
      const response = await getAIResponse(userMessage);
      setMessages(prev => [...prev, { role: 'assistant', content: response }]);
    } catch (error) {
      setMessages(prev => [
        ...prev,
        {
          role: 'assistant',
          content: 'Sorry, I encountered an error. Please try again.',
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const getAIResponse = async (question: string): Promise<string> => {
    await new Promise(resolve => setTimeout(resolve, 1000));

    const lowerQuestion = question.toLowerCase();

    if (lowerQuestion.includes('sql injection') || lowerQuestion.includes('sqli')) {
      return 'SQL Injection is a code injection technique that exploits vulnerabilities in an application\'s database layer. Attackers can:\n\n1. Bypass authentication (e.g., using \' OR \'1\'=\'1)\n2. Extract sensitive data\n3. Modify or delete data\n4. Execute admin operations\n\nPrevention:\n- Use parameterized queries/prepared statements\n- Input validation and sanitization\n- Principle of least privilege for database accounts\n- Use ORM frameworks when possible\n\nTry our SQL Injection lab to practice safely!';
    }

    if (lowerQuestion.includes('xss') || lowerQuestion.includes('cross-site scripting')) {
      return 'Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages. There are three main types:\n\n1. **Reflected XSS**: Script comes from current HTTP request\n2. **Stored XSS**: Script is stored in the database\n3. **DOM-based XSS**: Vulnerability in client-side code\n\nPrevention:\n- Encode output data\n- Validate input on server-side\n- Use Content Security Policy (CSP)\n- Sanitize HTML in user inputs\n- Use modern frameworks with built-in XSS protection\n\nCheck out our XSS lab to see it in action!';
    }

    if (lowerQuestion.includes('nmap') || lowerQuestion.includes('port scan')) {
      return 'Nmap (Network Mapper) is a powerful open-source tool for network discovery and security auditing.\n\nCommon commands:\n- `nmap -sS [target]` - TCP SYN scan (stealth scan)\n- `nmap -sV [target]` - Version detection\n- `nmap -O [target]` - OS detection\n- `nmap -A [target]` - Aggressive scan (OS, version, scripts)\n- `nmap -p- [target]` - Scan all 65535 ports\n\nEthical usage:\n- Only scan networks you own or have permission to test\n- Be aware of legal implications\n- Use responsibly for security assessments\n\nTry our Nmap simulator in the Security Tools section!';
    }

    if (lowerQuestion.includes('wireshark') || lowerQuestion.includes('packet')) {
      return 'Wireshark is a network protocol analyzer that captures and displays network packets in real-time.\n\nKey features:\n- Capture live packet data\n- Filter packets by protocol, source, destination\n- Decrypt encrypted traffic (with keys)\n- Follow TCP streams\n- Analyze network performance\n\nCommon use cases:\n- Network troubleshooting\n- Security analysis\n- Protocol development\n- Education and learning\n\nFilters:\n- `http` - Show only HTTP traffic\n- `ip.addr == 192.168.1.1` - Filter by IP\n- `tcp.port == 80` - Filter by port\n\nTry our Wireshark simulator in the Security Tools section!';
    }

    if (lowerQuestion.includes('csrf')) {
      return 'CSRF (Cross-Site Request Forgery) tricks users into executing unwanted actions on a web application where they\'re authenticated.\n\nHow it works:\n1. User logs into legitimate site\n2. Attacker tricks user into visiting malicious site\n3. Malicious site sends forged request to legitimate site\n4. Request executes with user\'s credentials\n\nPrevention:\n- Use CSRF tokens (random values per session)\n- Validate Origin/Referer headers\n- Use SameSite cookie attribute\n- Require re-authentication for sensitive actions\n- Use custom request headers\n\nExplore our CSRF lab to understand this vulnerability better!';
    }

    if (lowerQuestion.includes('encryption') || lowerQuestion.includes('decrypt')) {
      return 'Encryption is the process of encoding information so only authorized parties can access it.\n\nCommon algorithms:\n- **AES-256**: Symmetric encryption, very secure\n- **RSA**: Asymmetric encryption, used for key exchange\n- **ChaCha20**: Modern stream cipher\n\nKey concepts:\n- **Symmetric**: Same key for encryption and decryption\n- **Asymmetric**: Public key encrypts, private key decrypts\n- **Hashing**: One-way function (SHA-256, bcrypt)\n\nBest practices:\n- Use strong, random keys\n- Never store keys in code\n- Use established libraries\n- Keep software updated\n\nTry our Encryption/Decryption tools to practice!';
    }

    if (lowerQuestion.includes('password') || lowerQuestion.includes('strong password')) {
      return 'Strong passwords are essential for security!\n\nCharacteristics of strong passwords:\n- At least 12-16 characters long\n- Mix of uppercase and lowercase\n- Include numbers and special characters\n- Avoid dictionary words\n- Unique for each account\n\nBest practices:\n- Use a password manager\n- Enable 2FA/MFA when available\n- Never share passwords\n- Change passwords if compromised\n- Avoid password reuse\n\nCommon attacks:\n- Brute force: Trying all combinations\n- Dictionary: Using common words\n- Credential stuffing: Using leaked passwords\n\nUse our Password Analyzer tool to test strength!';
    }

    if (lowerQuestion.includes('authentication') || lowerQuestion.includes('auth bypass')) {
      return 'Authentication vulnerabilities allow attackers to bypass or compromise the login system.\n\nCommon vulnerabilities:\n1. **SQL Injection in login forms**\n2. **Weak password policies**\n3. **Session fixation**\n4. **Broken session management**\n5. **Insecure password reset**\n6. **Missing rate limiting**\n\nSecure authentication:\n- Hash passwords with bcrypt/Argon2\n- Implement account lockout\n- Use secure session management\n- Enable MFA\n- Validate on server-side\n- Use HTTPS only\n\nTry our Authentication Bypass lab!';
    }

    if (lowerQuestion.includes('access control') || lowerQuestion.includes('privilege')) {
      return 'Access Control ensures users can only access resources they\'re authorized for.\n\nTypes of vulnerabilities:\n1. **Horizontal privilege escalation**: Access other users\' data\n2. **Vertical privilege escalation**: Access admin functions\n3. **IDOR**: Insecure Direct Object Reference\n\nPrevention:\n- Implement role-based access control (RBAC)\n- Verify permissions server-side\n- Use indirect references\n- Deny by default\n- Test with different user roles\n\nPrinciple of least privilege:\n- Users should have minimum necessary access\n- Regularly review permissions\n- Remove access when no longer needed\n\nExplore our Broken Access Control lab!';
    }

    return 'That\'s an interesting question! I can help you with:\n\n- SQL Injection attacks and prevention\n- XSS (Cross-Site Scripting) vulnerabilities\n- Authentication and access control\n- Network tools like Nmap and Wireshark\n- Encryption and cryptography\n- Password security\n- CSRF attacks\n- And many other cybersecurity topics!\n\nFeel free to ask about any specific vulnerability or tool, or explore our interactive labs!';
  };

  return (
    <div className="flex flex-col h-[calc(100vh-12rem)] bg-white rounded-xl shadow-md">
      <div className="bg-gradient-to-r from-emerald-500 to-teal-600 p-4 rounded-t-xl">
        <div className="flex items-center space-x-3">
          <div className="bg-white p-2 rounded-lg">
            <Bot className="h-6 w-6 text-emerald-600" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">AI Security Assistant</h2>
            <p className="text-emerald-50 text-sm">Ask me anything about cybersecurity</p>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((message, index) => (
          <div
            key={index}
            className={`flex items-start space-x-3 ${
              message.role === 'user' ? 'flex-row-reverse space-x-reverse' : ''
            }`}
          >
            <div
              className={`p-2 rounded-lg ${
                message.role === 'user' ? 'bg-emerald-100' : 'bg-gray-100'
              }`}
            >
              {message.role === 'user' ? (
                <User className="h-5 w-5 text-emerald-600" />
              ) : (
                <Bot className="h-5 w-5 text-gray-600" />
              )}
            </div>
            <div
              className={`flex-1 p-4 rounded-lg ${
                message.role === 'user'
                  ? 'bg-emerald-50 border border-emerald-200'
                  : 'bg-gray-50 border border-gray-200'
              }`}
            >
              <p className="text-gray-800 whitespace-pre-line">{message.content}</p>
            </div>
          </div>
        ))}

        {isLoading && (
          <div className="flex items-start space-x-3">
            <div className="p-2 rounded-lg bg-gray-100">
              <Bot className="h-5 w-5 text-gray-600" />
            </div>
            <div className="flex-1 p-4 rounded-lg bg-gray-50 border border-gray-200">
              <Loader className="h-5 w-5 animate-spin text-gray-600" />
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      <div className="p-4 border-t border-gray-200">
        <div className="flex space-x-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleSend()}
            placeholder="Ask about vulnerabilities, tools, or security concepts..."
            className="flex-1 px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-emerald-500 focus:border-transparent"
            disabled={isLoading}
          />
          <button
            onClick={handleSend}
            disabled={!input.trim() || isLoading}
            className="px-6 py-3 bg-emerald-600 text-white rounded-lg hover:bg-emerald-700 disabled:bg-gray-400 transition-colors"
          >
            <Send className="h-5 w-5" />
          </button>
        </div>
      </div>
    </div>
  );
}
