import { Network, Wifi, Lock, Unlock, Terminal, Search } from 'lucide-react';

interface SecurityToolsProps {
  onToolSelect: (toolId: string) => void;
}

export function SecurityTools({ onToolSelect }: SecurityToolsProps) {
  const tools = [
    {
      id: 'nmap',
      name: 'Nmap Scanner',
      description: 'Network discovery and security auditing tool',
      icon: Network,
      color: 'from-blue-500 to-blue-600',
    },
    {
      id: 'wireshark',
      name: 'Wireshark Analyzer',
      description: 'Network protocol analyzer for packet inspection',
      icon: Wifi,
      color: 'from-cyan-500 to-cyan-600',
    },
    {
      id: 'encryption',
      name: 'File Encryption',
      description: 'Encrypt files using AES-256 encryption',
      icon: Lock,
      color: 'from-emerald-500 to-emerald-600',
    },
    {
      id: 'decryption',
      name: 'File Decryption',
      description: 'Decrypt encrypted files with the correct key',
      icon: Unlock,
      color: 'from-orange-500 to-orange-600',
    },
    {
      id: 'hash',
      name: 'Hash Generator',
      description: 'Generate cryptographic hashes (SHA-256)',
      icon: Terminal,
      color: 'from-purple-500 to-purple-600',
    },
    {
      id: 'password',
      name: 'Password Analyzer',
      description: 'Test password strength and get security recommendations',
      icon: Search,
      color: 'from-pink-500 to-pink-600',
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Security Tools</h1>
        <p className="text-gray-600 mt-2">
          Practice with real-world security tools and techniques. Click any tool to open it in full-screen mode.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {tools.map((tool) => {
          const Icon = tool.icon;

          return (
            <div
              key={tool.id}
              onClick={() => onToolSelect(tool.id)}
              className="bg-white rounded-xl shadow-md hover:shadow-2xl transition-all cursor-pointer overflow-hidden group"
            >
              <div className={`h-2 bg-gradient-to-r ${tool.color}`}></div>
              <div className="p-6">
                <div className="flex items-start justify-between mb-4">
                  <div className={`p-3 rounded-lg bg-gradient-to-r ${tool.color}`}>
                    <Icon className="h-6 w-6 text-white" />
                  </div>
                </div>
                <h3 className="text-xl font-bold text-gray-900 mb-2">{tool.name}</h3>
                <p className="text-gray-600 text-sm mb-4">{tool.description}</p>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-500">Click to open</span>
                  <span className="text-emerald-600 group-hover:translate-x-1 transition-transform">→</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
        <h3 className="font-semibold text-blue-900 mb-2">Pro Tip</h3>
        <p className="text-blue-800 text-sm">
          Each tool opens in full-screen mode for a better experience. Use these tools to practice network scanning, packet analysis, encryption, and password security testing.
        </p>
      </div>
    </div>
  );
}
