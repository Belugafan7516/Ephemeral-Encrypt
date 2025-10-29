import React, { useState, useEffect, useMemo } from 'react';
import { initializeApp } from 'firebase/app';
import { 
  getAuth, 
  signInAnonymously, 
  signInWithCustomToken, 
  onAuthStateChanged 
} from 'firebase/auth';
import { 
  getFirestore, 
  collection, 
  addDoc, 
  onSnapshot, 
  serverTimestamp,
  query,
  setLogLevel
} from 'firebase/firestore';
import { 
  CheckCircle, 
  XCircle, 
  Loader2, 
  KeyRound, 
  PenSquare, 
  History, 
  User,
  Copy
} from 'lucide-react';

// --- Firebase Configuration ---
// These global variables are provided by the environment when running in Canvas.
// For Vercel deployment, the code relies on App.jsx being the main file 
// (though Vercel variables are accessed differently, this ensures Canvas compatibility).
const appId = typeof __app_id !== 'undefined' ? __app_id : 'default-app-id';
const firebaseConfig = typeof __firebase_config !== 'undefined' ? JSON.parse(__firebase_config) : {};
const initialAuthToken = typeof __initial_auth_token !== 'undefined' ? __initial_auth_token : null;

// --- Crypto Configuration ---
const signAlgorithm = {
  name: "RSA-PSS",
  hash: "SHA-256",
};

const keyGenParams = {
  name: "RSA-PSS",
  modulusLength: 2048,
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
  hash: "SHA-256",
};

// --- Crypto Helper Functions ---
function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary_string = window.atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}

function str2ab(str) {
  return new TextEncoder().encode(str);
}

// --- React Components ---

/**
 * MessageItem Component
 * Renders a single signed message from the ledger.
 */
const MessageItem = ({ message, onVerify, verificationStatus }) => {
  const [showDetails, setShowDetails] = useState(false);

  const timestamp = message.timestamp?.toDate 
    ? message.timestamp.toDate().toLocaleString() 
    : 'Pending...';

  const status = verificationStatus?.id === message.id ? verificationStatus.status : null;

  const handleCopy = (text) => {
    // A fallback for document.execCommand
    try {
      const textArea = document.createElement("textarea");
      textArea.value = text;
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
    } catch (err) {
      console.error('Failed to copy text: ', err);
    }
  };
  
  // Adjusted handleCopy to use document.execCommand for better iframe compatibility
  const handleCopyKey = (text) => {
      try {
        const tempElement = document.createElement('textarea');
        tempElement.value = text;
        document.body.appendChild(tempElement);
        tempElement.select();
        document.execCommand('copy');
        document.body.removeChild(tempElement);
      } catch (err) {
        console.error('Failed to copy text using execCommand: ', err);
      }
  };

  
  return (
    <div className="bg-gray-800 rounded-lg shadow-md transition-all duration-300">
      <div className="p-4 border-b border-gray-700">
        <div className="flex justify-between items-center mb-2">
          <span className="text-xs font-mono text-cyan-300 break-all" title="User ID">
            {message.userId}
          </span>
          <span className="text-xs text-gray-400 flex-shrink-0 ml-2">{timestamp}</span>
        </div>
        <p className="text-gray-100 whitespace-pre-wrap">{message.message}</p>
      </div>
      
      <div className="p-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between">
          <button
            onClick={() => onVerify(message)}
            disabled={status === 'checking'}
            className="w-full sm:w-auto flex items-center justify-center px-4 py-2 bg-green-600 text-white rounded-md font-semibold hover:bg-green-700 transition duration-200 disabled:bg-gray-500 disabled:cursor-not-allowed"
          >
            {status === 'checking' && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
            {status === 'valid' && <CheckCircle className="w-4 h-4 mr-2" />}
            {status === 'invalid' && <XCircle className="w-4 h-4 mr-2" />}
            {status === null && <CheckCircle className="w-4 h-4 mr-2" />}
            Verify Signature
          </button>
          
          <div className="flex items-center justify-center mt-3 sm:mt-0">
            {status === 'valid' && (
              <span className="text-sm font-medium text-green-400">
                Signature is Valid
              </span>
            )}
            {status === 'invalid' && (
              <span className="text-sm font-medium text-red-400">
                Signature is Invalid
              </span>
            )}
            <button
              onClick={() => setShowDetails(!showDetails)}
              className="ml-4 text-sm text-gray-400 hover:text-white"
            >
              {showDetails ? 'Hide' : 'Show'} Details
            </button>
          </div>
        </div>
        
        {showDetails && (
          <div className="mt-4 space-y-4">
            {/* Using handleCopyKey for better iframe compatibility */}
            <KeyDisplay label="Public Key (Base64)" value={message.publicKey} onCopy={handleCopyKey} />
            <KeyDisplay label="Signature (Base64)" value={message.signature} onCopy={handleCopyKey} />
          </div>
        )}
      </div>
    </div>
  );
};

/**
 * KeyDisplay Component
 * A small helper to show cryptographic keys/signatures.
 */
const KeyDisplay = ({ label, value, onCopy }) => (
  <div>
    <div className="flex justify-between items-center mb-1">
      <label className="text-xs font-semibold text-gray-400">{label}</label>
      <button onClick={() => onCopy(value)} title="Copy" className="text-gray-500 hover:text-white">
        <Copy className="w-3 h-3" />
      </button>
    </div>
    <textarea
      readOnly
      value={value}
      rows="3"
      className="w-full p-2 bg-gray-900 text-gray-300 font-mono text-xs rounded-md border border-gray-700 resize-none"
    />
  </div>
);

/**
 * MainApplication Component
 * The core app UI shown after successful authentication.
 */
const MainApplication = ({ db, userId }) => {
  // App State
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  
  // Crypto State
  const [keyPair, setKeyPair] = useState(null);
  const [publicKeyB64, setPublicKeyB64] = useState('');
  const [privateKeyB64, setPrivateKeyB64] = useState('');
  
  // UI State
  const [isLoading, setIsLoading] = useState(false);
  const [isPosting, setIsPosting] = useState(false);
  const [verificationStatus, setVerificationStatus] = useState({ id: null, status: null }); // { id: 'msgId', status: 'valid' | 'invalid' | 'checking' }

  // Firestore Collection Path
  const collectionPath = useMemo(() => `/artifacts/${appId}/public/data/signed_messages`, []);

  // Effect for fetching messages
  useEffect(() => {
    if (!db || !userId) return;

    const q = query(collection(db, collectionPath));
    
    const unsubscribe = onSnapshot(q, (snapshot) => {
      const docs = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
      
      // Sort in-memory (newest first)
      docs.sort((a, b) => {
        const timeA = a.timestamp?.seconds || 0;
        const timeB = b.timestamp?.seconds || 0;
        return timeB - timeA;
      });
      
      setMessages(docs);
    }, (error) => {
      console.error("Error fetching messages: ", error);
    });

    return () => unsubscribe();
  }, [db, userId, collectionPath]);
  
  // --- Crypto Handlers ---

  const handleGenerateKeys = async () => {
    setIsLoading(true);
    try {
      const newKeyPair = await window.crypto.subtle.generateKey(
        keyGenParams,
        true, // extractable
        ["sign", "verify"]
      );

      const publicKeyBuffer = await window.crypto.subtle.exportKey("spki", newKeyPair.publicKey);
      const privateKeyBuffer = await window.crypto.subtle.exportKey("pkcs8", newKeyPair.privateKey);

      setKeyPair(newKeyPair);
      setPublicKeyB64(arrayBufferToBase64(publicKeyBuffer));
      setPrivateKeyB64(arrayBufferToBase64(privateKeyBuffer));

    } catch (err) {
      console.error("Key generation failed:", err);
    }
    setIsLoading(false);
  };

  const handleSignAndPost = async () => {
    if (!newMessage || !keyPair) {
      // Replaced alert with console message/validation display
      console.warn("Validation failed: Please generate keys and write a message first.");
      return;
    }
    
    setIsPosting(true);
    try {
      const messageBuffer = str2ab(newMessage);
      
      const signatureBuffer = await window.crypto.subtle.sign(
        signAlgorithm,
        keyPair.privateKey,
        messageBuffer
      );
      
      const signatureB64 = arrayBufferToBase64(signatureBuffer);

      // Post to Firestore
      await addDoc(collection(db, collectionPath), {
        userId: userId,
        message: newMessage,
        publicKey: publicKeyB64,
        signature: signatureB64,
        timestamp: serverTimestamp()
      });
      
      setNewMessage(''); // Clear input on success
      
    } catch (err) {
      console.error("Failed to sign and post message:", err);
    }
    setIsPosting(false);
  };
  
  const handleVerify = async (messageDoc) => {
    setVerificationStatus({ id: messageDoc.id, status: 'checking' });
    
    try {
      const { message, publicKey: pubKeyB64, signature: sigB64 } = messageDoc;

      // 1. Import the public key
      const publicKeyBuffer = base64ToArrayBuffer(pubKeyB64);
      const publicKey = await window.crypto.subtle.importKey(
        "spki",
        publicKeyBuffer,
        keyGenParams,
        true,
        ["verify"]
      );

      // 2. Convert message and signature
      const messageBuffer = str2ab(message);
      const signatureBuffer = base64ToArrayBuffer(sigB64);

      // 3. Verify
      const isValid = await window.crypto.subtle.verify(
        signAlgorithm,
        publicKey,
        signatureBuffer,
        messageBuffer
      );
      
      setVerificationStatus({ id: messageDoc.id, status: isValid ? 'valid' : 'invalid' });

    } catch (err) {
      console.error("Verification failed:", err);
      setVerificationStatus({ id: messageDoc.id, status: 'invalid' });
    }
  };

  return (
    <div className="w-full max-w-7xl mx-auto p-4 md:p-6 space-y-6">
      
      {/* Header */}
      <header className="bg-gray-800 p-4 rounded-lg shadow-lg flex flex-col md:flex-row justify-between items-center">
        <h1 className="text-3xl font-bold text-cyan-400">Signed Message Ledger</h1>
        <div className="flex items-center mt-2 md:mt-0 bg-gray-700 px-3 py-1 rounded-full">
          <User className="w-4 h-4 mr-2 text-cyan-300" />
          <span className="text-xs text-gray-300 font-mono" title="Your User ID">
            {userId}
          </span>
        </div>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column: Keys & Signing */}
        <div className="lg:col-span-1 space-y-6">

          {/* Key Management Card */}
          <div className="bg-gray-800 p-6 rounded-lg shadow-lg">
            <h2 className="text-2xl font-semibold text-gray-100 flex items-center mb-4">
              <KeyRound className="w-6 h-6 mr-3 text-cyan-400" />
              1. Key Management
            </h2>
            <p className="text-sm text-gray-400 mb-4">
              Generate a temporary key pair for this session. Your private key never leaves your browser.
            </p>
            <button
              onClick={handleGenerateKeys}
              disabled={isLoading}
              className="w-full flex items-center justify-center px-4 py-3 bg-cyan-600 text-white rounded-md font-semibold hover:bg-cyan-700 transition duration-200 disabled:bg-gray-500"
            >
              {isLoading && <Loader2 className="w-5 h-5 mr-2 animate-spin" />}
              {isLoading ? 'Generating...' : 'Generate New Key Pair'}
            </button>
            <div className="mt-4 space-y-3">
              {/* Note: navigator.clipboard.writeText is replaced by a safer helper in MessageItem */}
              <KeyDisplay label="Your Public Key (Base64)" value={publicKeyB64} onCopy={(val) => { 
                  try { document.execCommand('copy'); } catch(e) { console.error('Copy failed', e) }
              }} />
              <KeyDisplay label="Your Private Key (Base64)" value={privateKeyB64} onCopy={(val) => { 
                  try { document.execCommand('copy'); } catch(e) { console.error('Copy failed', e) }
              }} />
            </div>
          </div>

          {/* Sign Message Card */}
          <div className="bg-gray-800 p-6 rounded-lg shadow-lg">
            <h2 className="text-2xl font-semibold text-gray-100 flex items-center mb-4">
              <PenSquare className="w-6 h-6 mr-3 text-cyan-400" />
              2. Sign & Post
            </h2>
            <textarea
              value={newMessage}
              onChange={(e) => setNewMessage(e.target.value)}
              rows="5"
              placeholder={keyPair ? "Write your message to sign..." : "Please generate keys first..."}
              disabled={!keyPair || isPosting}
              className="w-full p-3 bg-gray-900 text-gray-200 rounded-md border border-gray-700 focus:ring-2 focus:ring-cyan-500 focus:outline-none"
            />
            <button
              onClick={handleSignAndPost}
              disabled={!keyPair || !newMessage || isPosting}
              className="w-full flex items-center justify-center mt-4 px-4 py-3 bg-blue-600 text-white rounded-md font-semibold hover:bg-blue-700 transition duration-200 disabled:bg-gray-500 disabled:cursor-not-allowed"
            >
              {isPosting && <Loader2 className="w-5 h-5 mr-2 animate-spin" />}
              {isPosting ? 'Posting...' : 'Sign and Post Message'}
            </button>
          </div>
        </div>

        {/* Right Column: Message History */}
        <div className="lg:col-span-2 bg-gray-800 p-6 rounded-lg shadow-lg">
          <h2 className="text-2xl font-semibold text-gray-100 flex items-center mb-4">
            <History className="w-6 h-6 mr-3 text-cyan-400" />
            3. Public Message Ledger
          </h2>
          <div className="h-[70vh] max-h-[800px] overflow-y-auto space-y-4 pr-2 bg-gray-900 p-4 rounded-md border border-gray-700">
            {messages.length === 0 ? (
              <div className="text-center text-gray-500 pt-10">
                <p>No messages yet.</p>
                <p>Be the first to post!</p>
              </div>
            ) : (
              messages.map(msg => (
                <MessageItem 
                  key={msg.id} 
                  message={msg} 
                  onVerify={handleVerify}
                  verificationStatus={verificationStatus}
                />
              ))
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
  const [userId, setUserId] = useState(null);
  const [isAuthReady, setIsAuthReady] = useState(false);

  useEffect(() => {
    // Initialize Firebase
    try {
      // Check if firebaseConfig is populated. If not, we can't initialize.
      if (Object.keys(firebaseConfig).length === 0) {
        console.error("Firebase config is empty. Cannot initialize.");
        setIsAuthReady(true); // Stop trying to connect, but show UI (or a warning)
        return;
      }
      
      const app = initializeApp(firebaseConfig);
      const authInstance = getAuth(app);
      const dbInstance = getFirestore(app);
      
      // Enable debug logging for Firestore
      setLogLevel('debug');

      setDb(dbInstance);
      setAuth(authInstance);

      // Set up auth state listener
      const unsubscribe = onAuthStateChanged(authInstance, async (user) => {
        if (user) {
          // User is signed in
          setUserId(user.uid);
          setIsAuthReady(true);
        } else {
          // User is signed out, attempt to sign in
          try {
            if (initialAuthToken) {
              await signInWithCustomToken(authInstance, initialAuthToken);
            } else {
              await signInAnonymously(authInstance);
            }
            // The onAuthStateChanged listener will fire again once signed in
          } catch (authError) {
            console.error("Anonymous sign-in failed: ", authError);
            setIsAuthReady(false); // Auth failed
          }
        }
      });
      
      return () => unsubscribe(); // Cleanup listener on unmount
      
    } catch (e) {
      console.error("Firebase initialization error:", e);
      setIsAuthReady(false); // Init failed
    }
  }, []);

  if (!isAuthReady || !db || !userId) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-900 text-white">
        <Loader2 className="w-8 h-8 mr-3 animate-spin text-cyan-400" />
        <span className="text-xl">Authenticating & Loading Ledger...</span>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 text-gray-200 font-sans">
      <MainApplication db={db} userId={userId} />
    </div>
  );
}
