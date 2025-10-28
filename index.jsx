import React, { useState, useEffect, useMemo, useRef } from 'react';
import { initializeApp } from 'firebase/app';
import { 
  getAuth, 
  signInAnonymously, 
  signInWithCustomToken, 
  onAuthStateChanged 
} from 'firebase/auth';
import { 
  getFirestore, 
  doc, 
  getDoc, 
  setDoc, 
  deleteDoc,
  serverTimestamp,
  setLogLevel
} from 'firebase/firestore';
import { 
  Loader2, 
  Lock, 
  KeyRound, 
  Eye, 
  Share2, 
  Send,
  Download,
  Clipboard,
  ClipboardCheck,
  AlertTriangle,
  FileText,
  Link as LinkIcon 
} from 'lucide-react';

// --- Firebase Configuration (UPDATED FOR VERCEL/VITE) ---
// We now read environment variables prefixed with VITE_
const appId = import.meta.env.VITE_APP_ID || 'default-app-id';
const firebaseConfig = JSON.parse(import.meta.env.VITE_FIREBASE_CONFIG || '{}'); 
// In a deployed environment, we sign in anonymously, so the custom token is set to null.
const initialAuthToken = null; 

// --- Crypto Configuration ---
const PBKDF2_ITERATIONS = 100000;
const ALGO_NAME = "AES-GCM";
const ALGO_LENGTH = 256; // 256-bit
const EXPIRY_DAYS = 14;
const EXPIRY_MS = EXPIRY_DAYS * 24 * 60 * 60 * 1000;

// --- Utility Functions ---

const helpers = {
  str2ab: (str) => new TextEncoder().encode(str),
  ab2str: (buf) => new TextDecoder().decode(buf),
  ab2base64: (buf) => {
    let binary = '';
    const bytes = new Uint8Array(buf);
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  },
  base642ab: (base64) => {
    const binary_string = window.atob(base64);
    const bytes = new Uint8Array(binary_string.length);
    for (let i = 0; i < binary_string.length; i++) {
      bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
  },
  
  getEncryptionKey: async (password, salt) => {
    const keyMaterial = await window.crypto.subtle.importKey(
      "raw",
      helpers.str2ab(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: ALGO_NAME, length: ALGO_LENGTH },
      true,
      ["encrypt", "decrypt"]
    );
  },

  encrypt: async (text, password) => {
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const key = await window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      await window.crypto.subtle.importKey(
        "raw",
        helpers.str2ab(password),
        "PBKDF2",
        false,
        ["deriveKey"]
      ),
      { name: ALGO_NAME, length: ALGO_LENGTH },
      true,
      ["encrypt", "decrypt"]
    );
    
    const ciphertext = await window.crypto.subtle.encrypt(
      { name: ALGO_NAME, iv: iv },
      key,
      helpers.str2ab(text)
    );
    
    return {
      ciphertext: helpers.ab2base64(ciphertext),
      salt: helpers.ab2base64(salt),
      iv: helpers.ab2base64(iv),
    };
  },
  
  decrypt: async (encryptedData, password) => {
    try {
      const salt = helpers.base642ab(encryptedData.salt);
      const iv = helpers.base642ab(encryptedData.iv);
      const ciphertext = helpers.base642ab(encryptedData.ciphertext);
      
      const key = await helpers.getEncryptionKey(password, salt);
      
      const decrypted = await window.crypto.subtle.decrypt(
        { name: ALGO_NAME, iv: iv },
        key,
        ciphertext
      );
      
      return helpers.ab2str(decrypted);
    } catch (e) {
      console.error("Decryption failed:", e);
      throw new Error("Invalid Access Code");
    }
  },
  
  // Custom simple Markdown renderer for various custom syntaxes
  renderMarkdown: (markdown) => {
    if (!markdown) return '';
    
    // 1. Line breaks and paragraphs
    let html = markdown
      .replace(/\n\n+/g, '</p><p>') // Multiple newlines -> paragraph break
      .replace(/\n/g, '<br/>'); // Single newline -> line break
      
    if (html.length > 0) {
        html = '<p>' + html + '</p>'; 
    }

    // 2. Custom Formatting (Order matters: multi-char delimiters first)
    
    // Superscript/Upline (==text==) -> <sup>text</sup>
    html = html.replace(/==(.*?)==/g, '<sup>$1</sup>');
    
    // Strikethrough (—text—) -> <del>text</del>
    html = html.replace(/—(.*?)—/g, '<del>$1</del>'); 

    // Underline (__text__) -> <u>text</u>
    html = html.replace(/__(.*?)__/g, '<u>$1</u>'); 

    // Bold (**text**) -> <strong>text</strong>
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    
    // Italic (*text*) -> <em>$1</em>
    html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');
    
    return html;
  }
};

const generateShareData = (shareId, password, encryptedData, location) => {
  // Hardcoded domain for direct link as requested by the user
  const baseDomain = "https://encrypt.eugeneevons.com";
  // Use the current path but override the domain
  const linkWithId = `${baseDomain}${location.pathname}?id=${shareId}`; 
  
  // Combine all Base64 cryptographic components (Ciphertext, Salt, IV)
  const rawEncryptedMessage = `${encryptedData.ciphertext}:${encryptedData.salt}:${encryptedData.iv}`; 
  
  // Updated secureText format with the raw encrypted data
  const secureText = `Hi! I wanna share you an encrypted message. 

Access code: ${password}

Link here: ${linkWithId}
Or, use this:
${rawEncryptedMessage}

PS: Use encrypt.eugeneevons.com for encrypted message!`;

  return { secureText, linkWithId, rawEncryptedMessage };
};

// --- Markdown Text Editor Component ---

const MarkdownEditor = ({ content, onChange, readOnly = false }) => {
    return (
        <div className="border border-gray-700 rounded-lg overflow-hidden">
            <div className="flex space-x-2 p-3 border-b border-gray-700 bg-gray-800 text-gray-400 items-center">
                <FileText className="w-4 h-4 mr-1 text-cyan-400"/>
                <span className="text-xs font-mono">
                  Markdown Input: **bold**, *italic*, __underline__, —strike—, ==sup==
                </span>
            </div>
            <textarea
                readOnly={readOnly}
                value={content}
                onChange={onChange}
                className={`w-full min-h-[200px] p-4 text-sm text-gray-200 focus:outline-none resize-none ${
                    readOnly 
                        ? 'bg-gray-800 cursor-default' 
                        : 'bg-gray-900 focus:ring-2 focus:ring-cyan-500'
                }`}
                placeholder={readOnly ? "Fetching secret..." : "Type your secret here. Use **bold**, __underline__, —strike—, or ==sup== for formatting."}
            />
        </div>
    );
};

// --- Main App Logic and Components ---

const Loader = ({ text }) => (
  <div className="flex flex-col items-center justify-center h-screen bg-gray-900 text-white">
    <Loader2 className="w-12 h-12 mb-4 animate-spin text-cyan-400" />
    <span className="text-xl">{text}</span>
  </div>
);

function useCopyToClipboard() {
  const [copied, setCopied] = useState(false);

  const copy = (text) => {
    try {
      const textArea = document.createElement("textarea");
      textArea.value = text;
      textArea.style.position = "fixed";
      textArea.style.opacity = "0";
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      document.execCommand('copy');
      
      document.body.removeChild(textArea);
      
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy text: ', err);
    }
  };

  return { copied, copy };
}


const EphemeralEncryptApp = ({ db, currentUserId }) => {
  const [view, setView] = useState('send');

  // Create Secret States
  const [message, setMessage] = useState('');
  const [sendPassword, setSendPassword] = useState('');
  
  // Receive Secret States
  const [receiveId, setReceiveId] = useState('');
  const [receivePassword, setReceivePassword] = useState('');
  const [decryptedData, setDecryptedData] = useState({ content: '', lastViewedAt: 0 });

  const [isLoading, setIsLoading] = useState(false);
  
  // Status for Create View
  const [status, setStatus] = useState({ 
    type: '', 
    message: '', 
    code: '', 
    shareData: null
  }); 

  const { copied, copy } = useCopyToClipboard();

  const collectionPath = useMemo(() => `/artifacts/${appId}/public/data/ephemeral_secrets_v2`, []);
  
  // Read URL parameters on load
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const id = params.get('id');

    if (id) {
      setView('receive');
      setReceiveId(id);
      // Clean the URL so subsequent shares/views don't use the same ID
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }, []); 

  // Reset logic for different views
  const resetSend = () => {
    setMessage('');
    setSendPassword('');
    setStatus({ type: '', message: '', code: '', shareData: null });
  };

  const resetReceive = () => {
    setReceiveId('');
    setReceivePassword('');
    setDecryptedData({ content: '', lastViewedAt: 0 });
    setStatus({ type: '', message: '', code: '', shareData: null });
  };
  
  const handleEncrypt = async () => {
    const rawContent = message;
    
    if (rawContent.trim().length === 0 || !sendPassword) {
      setStatus({ type: 'error', message: 'Please provide a message and an access code.' });
      return;
    }
    
    setIsLoading(true);
    setStatus({ type: 'info', message: 'Encrypting message and generating Share ID...' });
    
    try {
      // 1. ENCRYPT the content (plain markdown string)
      const encryptedData = await helpers.encrypt(rawContent, sendPassword);
      
      const shareId = crypto.randomUUID();
      
      const docRef = doc(db, collectionPath, shareId);
      await setDoc(docRef, {
        ciphertext: encryptedData.ciphertext,
        salt: encryptedData.salt,
        iv: encryptedData.iv,
        
        createdAt: serverTimestamp(),
        lastViewedAt: serverTimestamp(), // Initial timestamp for expiry tracking
        creatorId: currentUserId,
      });
      
      const shareData = generateShareData(shareId, sendPassword, encryptedData, window.location);

      setStatus({ 
        type: 'success', 
        message: shareId, // Store the Share ID here temporarily
        code: sendPassword,
        shareData: shareData
      });
      
      setMessage('');
      setSendPassword('');
      
    } catch (err) {
      console.error("Encryption error:", err);
      setStatus({ type: 'error', message: `Encryption failed: ${err.message}` });
    }
    setIsLoading(false);
  };
  
  const handleDecryptAndRefresh = async () => {
    if (!receiveId || !receivePassword) {
      setStatus({ type: 'error', message: 'Please provide the Share ID and Access Code.' });
      return;
    }
    
    setIsLoading(true);
    setStatus({ type: 'info', message: 'Fetching, checking expiry, and decrypting secret...' });
    setDecryptedData({ content: '', lastViewedAt: 0 });

    const docRef = doc(db, collectionPath, receiveId.trim());
    
    try {
      const docSnap = await getDoc(docRef);
      
      if (!docSnap.exists()) {
        setStatus({ type: 'error', message: 'Secret not found or ID is incorrect.' });
        setIsLoading(false);
        return;
      }
      
      const data = docSnap.data();
      const lastViewedTimestamp = data.lastViewedAt?.toMillis();
      const currentTime = Date.now();
      
      // 1. Check for Expiry
      if (lastViewedTimestamp && (currentTime - lastViewedTimestamp > EXPIRY_MS)) {
        await deleteDoc(docRef);
        setStatus({ type: 'error', message: `Secret expired! It was automatically deleted after ${EXPIRY_DAYS} days of inactivity.` });
        setIsLoading(false);
        return;
      }

      // 2. Decrypt the Message (plain markdown string)
      const encryptedData = {
        ciphertext: data.ciphertext,
        salt: data.salt,
        iv: data.iv,
      };
      
      const decryptedText = await helpers.decrypt(encryptedData, receivePassword);

      // 3. Refresh Timer (Overwrite with new timestamp)
      await setDoc(docRef, {
        ...data,
        lastViewedAt: serverTimestamp(), // Resets the 14-day timer
      });
      
      setDecryptedData({ content: decryptedText, lastViewedAt: currentTime });
      setStatus({ type: 'success', message: `Secret decrypted. Expiry timer has been reset to ${EXPIRY_DAYS} days.` });
      setReceiveId('');
      setReceivePassword('');
      
    } catch (err) {
      console.error("Operation error:", err);
      if (err.message === "Invalid Access Code") {
        setStatus({ type: 'error', message: 'Decryption failed. Invalid Access Code.' });
      } else {
        setStatus({ type: 'error', message: `An error occurred: ${err.message}` });
      }
    }
    setIsLoading(false);
  };

  
  // Determines which status object to render based on current view/subView
  const renderGeneralStatus = () => {
    if (!status.message) return null;
    if (status.type === 'success' && status.shareData) return renderShareOutput();
    
    const colors = {
      'info': 'bg-blue-900 border-blue-700 text-blue-200',
      'error': 'bg-red-900 border-red-700 text-red-200',
      'success': 'bg-green-900 border-green-700 text-green-200',
    };
    
    return (
      <div className={`p-4 rounded-lg border ${colors[status.type] || 'bg-gray-700'}`}>
        <p>{status.message}</p>
      </div>
    );
  };
  
  const renderShareOutput = () => {
    if (!status.message || !status.code || !status.shareData) return null;
    
    const shareText = status.shareData.secureText;

    return (
      <div className="p-4 rounded-lg bg-gray-700 border border-gray-600">
        <h3 className="font-bold text-lg text-cyan-400 mb-2">
          Secret Created Successfully!
        </h3>
        
        <div className="p-3 my-4 bg-green-900 rounded-lg border border-green-700 text-green-200">
            <p className='text-sm font-semibold'>
                <AlertTriangle className='w-4 h-4 inline-block mr-2' />
                **CRITICAL:** The secret is set to expire in **{EXPIRY_DAYS} days** unless it is viewed, which resets the timer.
            </p>
        </div>

        <div className="space-y-4 mb-4">
          {/* Direct Link (For visual confirmation) */}
          <div className="p-3 bg-gray-900 rounded-lg border border-cyan-700">
            <label className="block text-xs font-semibold text-cyan-400 mb-1">Direct Link (Visually Confirm URL and ID)</label>
            <div className="flex items-center">
              <LinkIcon className="w-4 h-4 mr-2 text-cyan-500 flex-shrink-0" />
              <a 
                href={status.shareData.linkWithId} 
                target="_blank" 
                rel="noopener noreferrer"
                className="font-mono text-gray-200 text-sm break-all flex-1 hover:underline"
              >
                {status.shareData.linkWithId}
              </a>
            </div>
          </div>
          
          {/* Access Code (For visual confirmation) */}
          <div className="p-3 bg-gray-900 rounded-lg border border-red-700">
            <label className="block text-xs font-semibold text-red-400 mb-1">Access Code (Decryption Key)</label>
            <div className="flex items-center">
              <Lock className="w-4 h-4 mr-2 text-red-500 flex-shrink-0" />
              <span className="font-mono text-gray-200 text-sm break-all flex-1">{status.code}</span>
            </div>
          </div>
        </div>
        
        {/* Full share text area */}
        <p className="text-sm text-gray-400 mb-2 font-semibold mt-4">
          Full Secure Sharing Text (Copy this entire block for the recipient):
        </p>
        <textarea
          readOnly
          value={shareText}
          rows={7}
          className="w-full bg-gray-900 text-gray-200 border border-gray-600 rounded-lg p-3 text-sm font-mono whitespace-pre-wrap"
        />
        <p className="text-xs text-yellow-400 mt-2">
            **Note:** The raw data string in the "Or, use this" section (ciphertext:salt:iv) is provided for completeness, but the recipient still needs the **Share ID** from the link to fetch the secret from the database.
        </p>
        <button
          onClick={() => copy(shareText)}
          className="w-full flex items-center justify-center mt-4 px-4 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-md font-semibold transition duration-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          {copied ? <ClipboardCheck className="w-5 h-5 mr-2" /> : <Clipboard className="w-5 h-5 mr-2" />}
          {copied ? 'Copied!' : 'Copy Full Secure Text'}
        </button>
        
        <button onClick={resetSend} className="mt-4 text-sm text-cyan-400 hover:underline w-full text-center">
          Create another secret
        </button>
      </div>
    );
  };


  return (
    <div className="min-h-screen bg-gray-900 text-gray-200 font-sans py-8">
      <div className="w-full max-w-2xl mx-auto p-4 md:p-8">
        <header className="text-center mb-8">
          <h1 className="text-4xl font-extrabold text-white mb-2">
            Ephemeral <span className="text-cyan-400">Encrypt</span>
          </h1>
          <p className="text-sm text-gray-400">User ID: <span className="font-mono text-xs text-gray-500 break-all">{currentUserId}</span></p>
          <p className="text-sm text-gray-400">Supports **bold**, *italics*, __underline__, —strike—, and ==sup==. Secrets expire automatically after <span className="font-bold text-cyan-400">{EXPIRY_DAYS} days</span> unless viewed.</p>
        </header>

        {/* View Toggler */}
        <div className="flex bg-gray-800 rounded-lg p-1 mb-6">
          <button
            onClick={() => { setView('send'); resetSend(); resetReceive(); }}
            className={`w-1/2 py-3 rounded-md font-semibold transition ${view === 'send' ? 'bg-cyan-600 text-white' : 'text-gray-300 hover:bg-gray-700'}`}
          >
            <Send className="w-5 h-5 inline-block mr-2" />
            Create Secret
          </button>
          <button
            onClick={() => { setView('receive'); resetSend(); resetReceive(); }}
            className={`w-1/2 py-3 rounded-md font-semibold transition ${view === 'receive' ? 'bg-cyan-600 text-white' : 'text-gray-300 hover:bg-gray-700'}`}
          >
            <Download className="w-5 h-5 inline-block mr-2" />
            View/Refresh Secret
          </button>
        </div>

        <div className="bg-gray-800 p-6 md:p-8 rounded-lg shadow-2xl">
          
          {/* --- CREATE SECRET VIEW --- */}
          {view === 'send' && !status.shareData && ( 
            <form onSubmit={(e) => { e.preventDefault(); handleEncrypt(); }} className="space-y-6">
              
              <div>
                <label htmlFor="message" className="block text-sm font-medium text-gray-300 mb-2">
                  Secret Message (Markdown)
                </label>
                <MarkdownEditor
                  content={message}
                  onChange={(e) => setMessage(e.target.value)}
                />
              </div>
              
              <div>
                <label htmlFor="send-password" className="block text-sm font-medium text-gray-300 mb-2">
                  Access Code (min 6 chars)
                </label>
                <div className="relative">
                  <Lock className="w-5 h-5 text-gray-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    id="send-password"
                    type="password"
                    className="w-full bg-gray-900 text-gray-200 border border-gray-700 rounded-lg pl-10 pr-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500"
                    placeholder="e.g., SecurePassword123"
                    value={sendPassword}
                    onChange={(e) => setSendPassword(e.target.value)}
                    minLength="6"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={isLoading || sendPassword.length < 6}
                className="w-full flex items-center justify-center bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-5 rounded-lg transition duration-300 ease-in-out focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-500 disabled:cursor-not-allowed"
              >
                {isLoading ? <Loader2 className="w-5 h-5 mr-2 animate-spin" /> : <Share2 className="w-5 h-5 mr-2" />}
                {isLoading ? 'Encrypting...' : 'Encrypt & Create Share ID'}
              </button>
            </form>
          )}

          {/* --- RECEIVE VIEW --- */}
          {view === 'receive' && decryptedData.content.length === 0 && (
            <form onSubmit={(e) => { e.preventDefault(); handleDecryptAndRefresh(); }} className="space-y-6">
              <div>
                <label htmlFor="receive-id" className="block text-sm font-medium text-gray-300 mb-2">
                  Share ID
                </label>
                <div className="relative">
                  <KeyRound className="w-5 h-5 text-gray-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    id="receive-id"
                    type="text"
                    className="w-full bg-gray-900 text-gray-200 border border-gray-700 rounded-lg pl-10 pr-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500 font-mono"
                    placeholder="Paste the Share ID here..."
                    value={receiveId}
                    onChange={(e) => setReceiveId(e.target.value)}
                  />
                </div>
              </div>
              
              <div>
                <label htmlFor="receive-password" className="block text-sm font-medium text-gray-300 mb-2">
                  Access Code
                </label>
                <div className="relative">
                  <Lock className="w-5 h-5 text-gray-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    id="receive-password"
                    type="password"
                    className="w-full bg-gray-900 text-gray-200 border border-gray-700 rounded-lg pl-10 pr-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500"
                    placeholder="Enter the Access Code..."
                    value={receivePassword}
                    onChange={(e) => setReceivePassword(e.target.value)}
                  />
                </div>
              </div>
              
              <button
                type="submit"
                disabled={isLoading || !receiveId || !receivePassword}
                className="w-full flex items-center justify-center bg-green-600 hover:bg-green-700 text-white font-bold py-3 px-5 rounded-lg transition duration-300 ease-in-out focus:outline-none focus:ring-2 focus:ring-green-500 disabled:bg-gray-500 disabled:cursor-not-allowed"
              >
                {isLoading ? <Loader2 className="w-5 h-5 mr-2 animate-spin" /> : <Eye className="w-5 h-5 mr-2" />}
                {isLoading ? 'Decrypting & Refreshing...' : 'Decrypt, View, & Refresh Timer'}
              </button>
            </form>
          )}
          
          {/* --- STATUS/RESULT AREA --- */}
          <div className="mt-6">
            {renderGeneralStatus()}
            
            {decryptedData.content.length > 0 && (
              <div className="p-4 rounded-lg bg-gray-900 border border-gray-700">
                <h3 className="font-bold text-lg text-cyan-400 mb-3 flex items-center">
                  <Eye className="w-5 h-5 mr-2 text-green-500" />
                  Decrypted Secret (Timer Refreshed!)
                </h3>
                <p className="text-sm text-green-400 mb-3">
                  The content is shown below with advanced Markdown formatting applied. The {EXPIRY_DAYS}-day expiry timer was reset upon viewing.
                </p>
                
                {/* Renders the decrypted Markdown content after conversion */}
                <div 
                    className='w-full p-4 text-sm bg-gray-800 text-gray-100 rounded-lg overflow-x-auto break-words space-y-2'
                    dangerouslySetInnerHTML={{ __html: helpers.renderMarkdown(decryptedData.content) }}
                />

                <div className='p-2 text-xs text-gray-500 bg-gray-800 border-t border-gray-700 mt-2 rounded-b-lg'>
                    Secret refreshed at: {new Date(decryptedData.lastViewedAt).toLocaleString()}
                </div>

                <button onClick={resetReceive} className="mt-4 text-sm text-cyan-400 hover:underline">
                  View another secret
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};


/**
 * App Component
 * Handles authentication and initialization.
 */
export default function App() {
  const [db, setDb] = useState(null);
  const [auth, setAuth] = useState(null);
  const [isAuthReady, setIsAuthReady] = useState(false);
  const [currentUserId, setCurrentUserId] = useState(null);

  useEffect(() => {
    // Check if the configuration is available before attempting to initialize
    if (!firebaseConfig || Object.keys(firebaseConfig).length === 0) {
      console.error("FIREBASE ERROR: Configuration is missing. Please set VITE_FIREBASE_CONFIG in your environment variables.");
      // Render a static error or loading state until config is found
      return; 
    }
    
    try {
      const app = initializeApp(firebaseConfig);
      const authInstance = getAuth(app);
      const dbInstance = getFirestore(app);
      
      setLogLevel('debug');
      setDb(dbInstance);
      setAuth(authInstance);

      const unsubscribe = onAuthStateChanged(authInstance, async (user) => {
        if (user) {
          setIsAuthReady(true);
          setCurrentUserId(user.uid);
        } else {
          try {
            if (initialAuthToken) {
              const credentials = await signInWithCustomToken(authInstance, initialAuthToken);
              setCurrentUserId(credentials.user.uid);
            } else {
              const credentials = await signInAnonymously(authInstance);
              setCurrentUserId(credentials.user.uid);
            }
            setIsAuthReady(true);
          } catch (authError) {
            console.error("Sign-in failed: ", authError);
          }
        }
      });
      
      return () => unsubscribe();
    } catch (e) {
      console.error("Firebase initialization error:", e);
    }
  }, []);

  if (!isAuthReady || !db) {
    // If we're waiting for auth/db initialization, show loader.
    return <Loader text="Connecting to Secure Service..." />;
  }
  
  // Final check to handle missing config in deployed environment
  if (Object.keys(firebaseConfig).length === 0) {
      return (
        <div className="min-h-screen bg-gray-900 flex items-center justify-center text-white p-4">
            <div className="bg-red-900 border border-red-700 p-6 rounded-lg max-w-sm text-center">
                <AlertTriangle className="w-8 h-8 mx-auto mb-3 text-red-300"/>
                <h2 className="text-xl font-bold mb-2">Configuration Error</h2>
                <p className="text-sm">The application cannot start. Please ensure the 
                <code className='bg-red-700/50 p-1 rounded-sm'>VITE_FIREBASE_CONFIG</code> 
                environment variable is set correctly in Vercel.</p>
            </div>
        </div>
      );
  }


  return (
    <div className="min-h-screen bg-gray-900 text-gray-200 font-sans py-8">
      <EphemeralEncryptApp db={db} currentUserId={currentUserId} />
    </div>
  );
}

