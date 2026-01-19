import { useState } from 'react';
import { Mic, MicOff, Volume2, VolumeX, X } from 'lucide-react';

interface VoiceGuideProps {
  onClose: () => void;
}

export function VoiceGuide({ onClose }: VoiceGuideProps) {
  const [isListening, setIsListening] = useState(false);
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [transcript, setTranscript] = useState('');
  const [response, setResponse] = useState('');
  const [isMinimized, setIsMinimized] = useState(false);

  const SpeechRecognition = (window as any).SpeechRecognition || (window as any).webkitSpeechRecognition;

  const startListening = () => {
    if (!SpeechRecognition) {
      alert('Speech Recognition not supported in this browser');
      return;
    }

    const recognition = new SpeechRecognition();
    recognition.lang = 'en-US';
    recognition.interimResults = true;

    recognition.onstart = () => setIsListening(true);
    recognition.onend = () => setIsListening(false);

    recognition.onresult = (event: any) => {
      let interim = '';
      for (let i = event.resultIndex; i < event.results.length; i++) {
        const transcriptPart = event.results[i][0].transcript;
        if (event.results[i].isFinal) {
          setTranscript((prev) => prev + ' ' + transcriptPart);
          handleVoiceQuestion(transcriptPart);
        } else {
          interim += transcriptPart;
        }
      }
    };

    recognition.start();
  };

  const handleVoiceQuestion = (question: string) => {
    const response = getVoiceResponse(question.toLowerCase());
    setResponse(response);
    speakResponse(response);
  };

  const getVoiceResponse = (question: string): string => {
    if (question.includes('help') || question.includes('guide')) {
      return "Welcome to CyberSec Academy! Here's a quick tour:\n\n1. Start with Vulnerability Labs to learn about different attack types\n2. Try Security Tools for hands-on practice\n3. Follow the Learning Path for structured curriculum\n4. Check your Progress to track achievements\n5. Use the AI Assistant for detailed guidance\n\nWhat would you like to explore first?";
    }

    if (question.includes('lab') || question.includes('vulnerability')) {
      return "The Vulnerability Labs section contains 8 different types of attacks including SQL Injection, XSS, and more. Each lab opens a vulnerable store where you can practice exploitation techniques safely. Start with beginner labs and progress to advanced ones!";
    }

    if (question.includes('tool')) {
      return "We have 6 security tools available: Nmap Scanner for network discovery, Wireshark for packet analysis, Encryption and Decryption tools, Hash Generator, and Password Analyzer. Click any tool to open it in full-screen mode for better experience!";
    }

    if (question.includes('learning') || question.includes('path')) {
      return "The Learning Path provides a structured curriculum from beginner to advanced level. Each level contains multiple modules. Complete modules to unlock certifications and advance your skills!";
    }

    if (question.includes('progress')) {
      return "Track your achievements in the Progress section. You can see your total points, completed labs, current streak, and earned badges. Keep learning to unlock more achievements!";
    }

    if (question.includes('sql') || question.includes('injection')) {
      return "SQL Injection is when attackers manipulate database queries through user input. Try payloads like ' OR '1'='1 to bypass authentication. Always use parameterized queries in real applications!";
    }

    if (question.includes('xss')) {
      return "Cross-Site Scripting lets attackers inject malicious scripts into web pages. Common payloads include script tags and event handlers. Remember to always validate and sanitize user input!";
    }

    if (question.includes('how does') || question.includes('what is')) {
      return "Ask me about specific topics like SQL Injection, XSS, tools, labs, or learning paths, and I'll explain them to you. Or say 'help' for a general guide!";
    }

    if (question.includes('start')) {
      return "Great! I recommend starting with the Vulnerability Labs. Click on the Vulnerability Labs tab, choose a beginner difficulty lab, and try exploiting it. The lab assistant will guide you through it!";
    }

    return "That's interesting! I can help you with questions about labs, tools, security concepts, or how to navigate the platform. What would you like to know?";
  };

  const speakResponse = (text: string) => {
    if ('speechSynthesis' in window) {
      const utterance = new SpeechSynthesisUtterance(text);
      utterance.rate = 0.9;
      utterance.pitch = 1;
      utterance.volume = 1;
      window.speechSynthesis.cancel();
      window.speechSynthesis.speak(utterance);
      setIsSpeaking(true);
      utterance.onend = () => setIsSpeaking(false);
    }
  };

  const stopSpeech = () => {
    if ('speechSynthesis' in window) {
      window.speechSynthesis.cancel();
      setIsSpeaking(false);
    }
  };

  if (isMinimized) {
    return (
      <div
        onClick={() => setIsMinimized(false)}
        className="fixed bottom-4 right-4 bg-gradient-to-r from-emerald-600 to-teal-600 text-white p-4 rounded-full shadow-lg cursor-pointer hover:shadow-xl transition-shadow hover:scale-110 transform"
        title="Click to expand"
      >
        <Mic className="h-6 w-6" />
      </div>
    );
  }

  return (
    <div className="fixed bottom-4 right-4 w-96 bg-white rounded-xl shadow-2xl border border-gray-200 overflow-hidden">
      <div className="bg-gradient-to-r from-emerald-600 to-teal-600 text-white p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Volume2 className="h-5 w-5" />
            <span className="font-semibold">Voice Guide</span>
          </div>
          <div className="flex space-x-2">
            <button
              onClick={() => setIsMinimized(true)}
              className="p-1 hover:bg-white/20 rounded transition-colors"
              title="Minimize"
            >
              <VolumeX className="h-4 w-4" />
            </button>
            <button
              onClick={onClose}
              className="p-1 hover:bg-white/20 rounded transition-colors"
              title="Close"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>

      <div className="p-6 space-y-4 max-h-96 overflow-y-auto">
        <div>
          <h3 className="font-semibold text-gray-900 mb-3">Voice Commands</h3>
          <p className="text-sm text-gray-600 mb-4">
            Click the microphone to speak naturally. Ask about labs, tools, concepts, or getting started!
          </p>
        </div>

        {transcript && (
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
            <p className="text-xs font-semibold text-blue-900 mb-1">Your Speech:</p>
            <p className="text-sm text-blue-800">{transcript}</p>
          </div>
        )}

        {response && (
          <div className="bg-emerald-50 border border-emerald-200 rounded-lg p-3">
            <p className="text-xs font-semibold text-emerald-900 mb-1">Response:</p>
            <p className="text-sm text-emerald-800 whitespace-pre-line">{response}</p>
          </div>
        )}

        <div className="flex space-x-2 pt-4">
          <button
            onClick={startListening}
            disabled={isListening}
            className="flex-1 flex items-center justify-center space-x-2 bg-emerald-600 text-white py-3 rounded-lg hover:bg-emerald-700 disabled:bg-gray-400 transition-colors font-semibold"
          >
            <Mic className="h-5 w-5" />
            <span>{isListening ? 'Listening...' : 'Click to Speak'}</span>
          </button>

          {isSpeaking && (
            <button
              onClick={stopSpeech}
              className="px-4 py-3 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors"
              title="Stop speaking"
            >
              <VolumeX className="h-5 w-5" />
            </button>
          )}
        </div>

        <div className="bg-gray-50 border border-gray-200 rounded-lg p-3">
          <p className="text-xs font-semibold text-gray-700 mb-2">Try asking:</p>
          <div className="space-y-1 text-xs text-gray-600">
            <p>• "Show me the labs"</p>
            <p>• "What are security tools?"</p>
            <p>• "Help me get started"</p>
            <p>• "Explain SQL Injection"</p>
            <p>• "How do I use this?"</p>
          </div>
        </div>
      </div>
    </div>
  );
}
