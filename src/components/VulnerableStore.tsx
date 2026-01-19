import { useState } from 'react';
import { ShoppingCart, AlertTriangle, CheckCircle, X, User } from 'lucide-react';
import { LabAIAssistant } from './LabAIAssistant';

interface VulnerableStoreProps {
  vulnerabilityType: string;
  onClose: () => void;
}

interface Product {
  id: string;
  name: string;
  price: number;
  description: string;
  image_url: string;
}

interface VulnInfo {
  title: string;
  hint: string;
  description: string;
  instructions: string[];
}

export function VulnerableStore({ vulnerabilityType, onClose }: VulnerableStoreProps) {
  const [products] = useState<Product[]>([
    {
      id: '1',
      name: 'Laptop',
      price: 999.99,
      description: 'High-performance laptop',
      image_url: 'https://images.pexels.com/photos/18105/pexels-photo.jpg?auto=compress&cs=tinysrgb&w=400',
    },
    {
      id: '2',
      name: 'Security Book',
      price: 49.99,
      description: 'Cybersecurity guide',
      image_url: 'https://images.pexels.com/photos/159711/books-bookstore-book-reading-159711.jpeg?auto=compress&cs=tinysrgb&w=400',
    },
    {
      id: '3',
      name: 'Wireless Adapter',
      price: 79.99,
      description: 'WiFi adapter',
      image_url: 'https://images.pexels.com/photos/163100/circuit-circuit-board-resistor-computer-163100.jpeg?auto=compress&cs=tinysrgb&w=400',
    },
    {
      id: '4',
      name: 'Raspberry Pi Kit',
      price: 129.99,
      description: 'Complete kit',
      image_url: 'https://images.pexels.com/photos/3888151/pexels-photo-3888151.jpeg?auto=compress&cs=tinysrgb&w=400',
    },
  ]);

  const [searchQuery, setSearchQuery] = useState('');
  const [loginUsername, setLoginUsername] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [exploitMessage, setExploitMessage] = useState('');
  const [showExploitAlert, setShowExploitAlert] = useState(false);
  const [currentUserId, setCurrentUserId] = useState(1);
  const [viewingUserId, setViewingUserId] = useState(1);
  const [displayHtml, setDisplayHtml] = useState('');

  const vulnerabilityInfo: Record<string, VulnInfo> = {
    'sql-injection': {
      title: 'SQL Injection Lab',
      hint: '\' OR \'1\'=\'1',
      description: 'Search queries are concatenated into SQL without sanitization',
      instructions: [
        'Try searching: \' OR \'1\'=\'1',
        'This closes the quote and adds OR TRUE',
        'The query becomes: SELECT * FROM products WHERE name LIKE \'%\' OR \'1\'=\'1%\'',
        'Returns all products because 1=1 is always true',
      ],
    },
    'xss': {
      title: 'Cross-Site Scripting (XSS) Lab',
      hint: '<script>alert("XSS")</script>',
      description: 'User input is directly inserted into HTML without sanitization',
      instructions: [
        'Try: <script>alert("XSS")</script>',
        'Or: <img src=x onerror=alert(document.cookie)>',
        'JavaScript executes in your browser',
        'Real attacks steal cookies and sessions',
      ],
    },
    'html-injection': {
      title: 'HTML Injection Lab',
      hint: '<h1 style="color:red">HACKED</h1>',
      description: 'HTML elements can be injected to modify page structure',
      instructions: [
        'Try: <h1 style="color:red">HACKED</h1>',
        'Or: <marquee>Scrolling!</marquee>',
        'Try: <iframe src="https://example.com" width="100%">',
        'You can inject any HTML to deface pages',
      ],
    },
    'auth-bypass': {
      title: 'Authentication Bypass Lab',
      hint: 'admin\'--',
      description: 'Multiple authentication flaws allow unauthorized access',
      instructions: [
        'Method 1: Username: admin\'--',
        'The -- comments out the password check',
        'Method 2: Default credentials: admin / admin',
        'Successfully login without valid password',
      ],
    },
    'broken-access': {
      title: 'Broken Access Control (IDOR) Lab',
      hint: 'Click different user IDs',
      description: 'No authorization checks before showing user data',
      instructions: [
        'Login with admin/admin or user/user',
        'Click different User buttons (1-5)',
        'Notice you can view ANY user\'s data',
        'Access sensitive info without permission',
      ],
    },
    'csrf': {
      title: 'Cross-Site Request Forgery Lab',
      hint: 'No CSRF tokens present',
      description: 'No CSRF token validation allows forged requests',
      instructions: [
        'Login first (admin/admin)',
        'Notice there are no CSRF tokens',
        'External sites can submit forms as you',
        'Actions execute with your authentication',
      ],
    },
  };

  const info = vulnerabilityInfo[vulnerabilityType] || vulnerabilityInfo['sql-injection'];

  const handleSearch = (query: string) => {
    setSearchQuery(query);

    if (vulnerabilityType === 'sql-injection') {
      if (query.toLowerCase().includes("' or '1'='1") ||
          query.toLowerCase().includes("' or 1=1") ||
          query.toLowerCase().includes("'or'1'='1")) {
        setExploitMessage('SQL Injection Success! The query returned ALL products. Query: SELECT * FROM products WHERE name LIKE \'%' + query + '%\' - The OR condition makes it always true!');
        setShowExploitAlert(true);
        setTimeout(() => setShowExploitAlert(false), 8000);
      }
    }

    if (vulnerabilityType === 'xss') {
      if (query.includes('<script>') || query.includes('onerror=') || query.includes('onload=')) {
        setExploitMessage('XSS Success! JavaScript payload executed. Real attacks steal cookies: document.cookie, or redirect to phishing sites!');
        setShowExploitAlert(true);
        setTimeout(() => setShowExploitAlert(false), 8000);

        try {
          if (query.toLowerCase().includes('alert')) {
            const match = query.match(/alert\s*\(\s*['"`]?(.+?)['"`]?\s*\)/i);
            if (match) {
              alert('XSS Demo: ' + match[1]);
            } else {
              alert('XSS Demo!');
            }
          }
        } catch (e) {
          console.log('XSS demonstration');
        }
      }
    }

    if (vulnerabilityType === 'html-injection') {
      if (query.includes('<') && query.includes('>')) {
        setExploitMessage('HTML Injection Success! Your HTML was rendered. You can inject any HTML elements to deface pages or trick users!');
        setShowExploitAlert(true);
        setDisplayHtml(query);
        setTimeout(() => {
          setShowExploitAlert(false);
          setDisplayHtml('');
        }, 8000);
      }
    }
  };

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();

    if (vulnerabilityType === 'auth-bypass' || vulnerabilityType === 'broken-access') {
      if (loginUsername.includes("'--") ||
          loginUsername.includes("' --") ||
          loginUsername.includes("'#") ||
          loginUsername.toLowerCase().includes("' or '1'='1")) {
        setIsLoggedIn(true);
        setCurrentUserId(1);
        setExploitMessage('SQL Injection Bypass! Query: SELECT * FROM users WHERE username=\'' + loginUsername + '\' AND password=\'' + loginPassword + '\' - The -- comments out password check!');
        setShowExploitAlert(true);
        setTimeout(() => setShowExploitAlert(false), 8000);
      } else if ((loginUsername === 'admin' && loginPassword === 'admin') ||
                 (loginUsername === 'user' && loginPassword === 'user')) {
        setIsLoggedIn(true);
        setCurrentUserId(loginUsername === 'admin' ? 1 : 2);
        setExploitMessage('Default Credentials Found! Login successful with: ' + loginUsername + ' / ' + loginPassword);
        setShowExploitAlert(true);
        setTimeout(() => setShowExploitAlert(false), 5000);
      } else {
        setExploitMessage('Login failed. Try: admin/admin or admin\'--');
        setShowExploitAlert(true);
        setTimeout(() => setShowExploitAlert(false), 3000);
      }
    }
  };

  const handleViewProfile = (userId: number) => {
    setViewingUserId(userId);
    if (userId !== currentUserId) {
      setExploitMessage('IDOR Success! Accessed User #' + userId + '\'s profile without authorization. This is Broken Access Control (IDOR)!');
      setShowExploitAlert(true);
      setTimeout(() => setShowExploitAlert(false), 8000);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4 overflow-y-auto">
      <div className="bg-white rounded-xl shadow-2xl max-w-6xl w-full max-h-[90vh] overflow-y-auto">
        <div className="sticky top-0 bg-white border-b border-gray-200 px-6 py-4 flex items-center justify-between z-10">
          <div>
            <h2 className="text-2xl font-bold text-gray-900">{info.title}</h2>
            <p className="text-sm text-gray-600 mt-1">{info.description}</p>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <X className="h-6 w-6" />
          </button>
        </div>

        {showExploitAlert && (
          <div className="mx-6 mt-4 bg-emerald-50 border-2 border-emerald-300 rounded-lg p-4 flex items-start space-x-3 animate-pulse">
            <CheckCircle className="h-6 w-6 text-emerald-600 flex-shrink-0 mt-0.5" />
            <div>
              <h3 className="font-bold text-emerald-900">Exploit Successful!</h3>
              <p className="text-emerald-800 text-sm mt-1">{exploitMessage}</p>
            </div>
          </div>
        )}

        <div className="p-6 space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
            <div className="lg:col-span-3 space-y-6">

          {(vulnerabilityType === 'auth-bypass' || vulnerabilityType === 'broken-access') && !isLoggedIn && (
            <div className="bg-white border-2 border-gray-300 rounded-lg p-6 max-w-md mx-auto shadow-lg">
              <div className="flex items-center space-x-2 mb-4">
                <User className="h-6 w-6 text-gray-600" />
                <h3 className="text-xl font-bold text-gray-900">Admin Login</h3>
              </div>
              <form onSubmit={handleLogin} className="space-y-4">
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-2">
                    Username
                  </label>
                  <input
                    type="text"
                    value={loginUsername}
                    onChange={(e) => setLoginUsername(e.target.value)}
                    className="w-full px-4 py-3 border-2 border-gray-300 rounded-lg focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500"
                    placeholder="admin"
                  />
                </div>
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-2">
                    Password
                  </label>
                  <input
                    type="password"
                    value={loginPassword}
                    onChange={(e) => setLoginPassword(e.target.value)}
                    className="w-full px-4 py-3 border-2 border-gray-300 rounded-lg focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500"
                    placeholder="password"
                  />
                </div>
                <button
                  type="submit"
                  className="w-full bg-emerald-600 text-white py-3 rounded-lg hover:bg-emerald-700 transition-colors font-semibold"
                >
                  Login
                </button>
              </form>
            </div>
          )}

          <div className="bg-yellow-50 border-2 border-yellow-300 rounded-lg p-5">
                <div className="flex items-start space-x-3 mb-3">
                  <AlertTriangle className="h-6 w-6 text-yellow-600 flex-shrink-0 mt-0.5" />
                  <div className="flex-1">
                    <h3 className="font-bold text-yellow-900 text-lg">Lab Instructions</h3>
                    <p className="text-yellow-800 text-sm mt-1">{info.description}</p>
                  </div>
                </div>
                <div className="bg-white rounded-lg p-4 space-y-2">
                  <p className="text-sm font-bold text-gray-900">Step-by-step:</p>
                  {info.instructions.map((step, idx) => (
                    <div key={idx} className="flex items-start space-x-2">
                      <span className="flex-shrink-0 w-6 h-6 bg-emerald-100 text-emerald-700 rounded-full flex items-center justify-center text-xs font-bold">
                        {idx + 1}
                      </span>
                      <p className="text-sm text-gray-700 pt-0.5">{step}</p>
                    </div>
                  ))}
                </div>
                <div className="mt-3 bg-red-100 border-2 border-red-300 rounded-lg p-3">
                  <p className="text-sm font-bold text-red-900">
                    Quick Payload:
                    <span className="ml-2 font-mono bg-white px-3 py-1 rounded border border-red-300">
                      {info.hint}
                    </span>
                  </p>
                </div>
              </div>

          {(vulnerabilityType !== 'auth-bypass' && vulnerabilityType !== 'broken-access' || isLoggedIn) &&
           vulnerabilityType !== 'broken-access' && (
            <>
              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2">
                  Search Products
                </label>
                <input
                  type="text"
                  placeholder="Try your payload here..."
                  value={searchQuery}
                  onChange={(e) => handleSearch(e.target.value)}
                  className="w-full px-4 py-3 border-2 border-gray-300 rounded-lg focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500"
                />
                {searchQuery && (
                  <div className="mt-3 space-y-2">
                    <div className="bg-gray-100 border border-gray-300 rounded-lg p-3">
                      <p className="text-xs font-semibold text-gray-600 mb-1">Your Input:</p>
                      <p className="text-sm font-mono text-gray-900">{searchQuery}</p>
                    </div>
                    {displayHtml && (
                      <div className="bg-white border-2 border-orange-400 rounded-lg p-4">
                        <p className="text-xs font-bold text-orange-900 mb-2">Rendered HTML (Vulnerability!):</p>
                        <div className="border-2 border-dashed border-orange-300 rounded p-3" dangerouslySetInnerHTML={{ __html: displayHtml }} />
                      </div>
                    )}
                  </div>
                )}
              </div>

              {vulnerabilityType === 'csrf' && isLoggedIn && (
                <div className="bg-blue-50 border-2 border-blue-300 rounded-lg p-5">
                  <h3 className="font-bold text-blue-900 mb-3 text-lg">CSRF Attack Demonstration</h3>
                  <p className="text-sm text-blue-800 mb-4">
                    You're logged in. Notice there's no CSRF token on forms. An attacker creates this HTML:
                  </p>
                  <pre className="bg-gray-900 text-green-400 p-4 rounded-lg text-xs overflow-x-auto font-mono">
{`<!-- Attacker's website (evil.com) -->
<form id="csrf" action="https://vulnstore.com/transfer" method="POST">
  <input name="amount" value="1000" />
  <input name="to_account" value="attacker" />
</form>
<script>
  // Auto-submit when victim visits
  document.getElementById('csrf').submit();
</script>`}
                  </pre>
                  <p className="text-sm text-blue-800 mt-4 font-semibold">
                    When you visit evil.com, the form submits using YOUR session cookie!
                  </p>
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                {products.map((product) => (
                  <div
                    key={product.id}
                    className="bg-white border-2 border-gray-200 rounded-lg overflow-hidden hover:shadow-lg transition-all"
                  >
                    <img
                      src={product.image_url}
                      alt={product.name}
                      className="w-full h-40 object-cover"
                    />
                    <div className="p-4">
                      <h3 className="font-bold text-gray-900 mb-1">{product.name}</h3>
                      <p className="text-xs text-gray-600 mb-3">{product.description}</p>
                      <div className="flex items-center justify-between">
                        <span className="text-lg font-bold text-emerald-600">
                          ${product.price}
                        </span>
                        <button className="p-2 bg-emerald-100 text-emerald-600 rounded-lg hover:bg-emerald-200 transition-colors">
                          <ShoppingCart className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}

          {vulnerabilityType === 'broken-access' && isLoggedIn && (
            <div className="space-y-6">
              <div className="bg-emerald-50 border-2 border-emerald-300 rounded-lg p-4">
                <p className="text-sm font-semibold text-emerald-900">
                  Logged in as: <span className="font-bold text-lg">User #{currentUserId}</span>
                </p>
              </div>

              <div>
                <h3 className="text-xl font-bold text-gray-900 mb-4">View User Profiles (IDOR Test)</h3>
                <div className="flex flex-wrap gap-3 mb-6">
                  {[1, 2, 3, 4, 5].map((userId) => (
                    <button
                      key={userId}
                      onClick={() => handleViewProfile(userId)}
                      className={`px-6 py-3 rounded-lg font-bold transition-all ${
                        viewingUserId === userId
                          ? 'bg-emerald-600 text-white shadow-lg scale-105'
                          : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                      }`}
                    >
                      User {userId}
                    </button>
                  ))}
                </div>

                <div className="bg-white border-2 border-gray-300 rounded-lg p-6 shadow-lg">
                  <div className="flex items-start justify-between mb-4">
                    <h4 className="text-lg font-bold text-gray-900">User Profile #{viewingUserId}</h4>
                    {viewingUserId !== currentUserId && (
                      <span className="px-4 py-2 bg-red-100 text-red-700 rounded-full text-sm font-bold animate-pulse">
                        Unauthorized Access!
                      </span>
                    )}
                  </div>
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div className="bg-gray-50 p-3 rounded-lg">
                      <p className="text-gray-600 font-semibold mb-1">Email</p>
                      <p className="font-bold text-gray-900">user{viewingUserId}@example.com</p>
                    </div>
                    <div className="bg-gray-50 p-3 rounded-lg">
                      <p className="text-gray-600 font-semibold mb-1">Full Name</p>
                      <p className="font-bold text-gray-900">John Doe #{viewingUserId}</p>
                    </div>
                    <div className="bg-gray-50 p-3 rounded-lg">
                      <p className="text-gray-600 font-semibold mb-1">Phone</p>
                      <p className="font-bold text-gray-900">+1-555-{String(1000 + viewingUserId).padStart(4, '0')}</p>
                    </div>
                    <div className="bg-gray-50 p-3 rounded-lg">
                      <p className="text-gray-600 font-semibold mb-1">Balance</p>
                      <p className="font-bold text-emerald-600">${(viewingUserId * 1234.56).toFixed(2)}</p>
                    </div>
                    <div className="bg-gray-50 p-3 rounded-lg">
                      <p className="text-gray-600 font-semibold mb-1">Credit Card</p>
                      <p className="font-bold text-gray-900">**** **** **** {1000 + viewingUserId}</p>
                    </div>
                    <div className="bg-gray-50 p-3 rounded-lg">
                      <p className="text-gray-600 font-semibold mb-1">SSN</p>
                      <p className="font-bold text-gray-900">***-**-{String(1000 + viewingUserId).padStart(4, '0')}</p>
                    </div>
                  </div>
                </div>

                <div className="mt-4 bg-red-50 border-2 border-red-300 rounded-lg p-4">
                  <p className="text-sm text-red-900">
                    <span className="font-bold text-base">Security Flaw:</span> You can view ANY user's sensitive data by clicking buttons.
                    The application doesn't verify authorization! This is called IDOR (Insecure Direct Object Reference).
                  </p>
                </div>
              </div>
            </div>
          )}
            </div>

            <div className="lg:col-span-1">
              <LabAIAssistant vulnerabilityType={vulnerabilityType} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
