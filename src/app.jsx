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
  Copy,
  AlertTriangle
} from 'lucide-react';

// --- Firebase Configuration ---
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
 * KeyDisplay Component - Updated to handle copy internally.
 */
const KeyDisplay = ({ label, value }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    if (!value) return;
    try {
      const tempElement = document.createElement('textarea');
      tempElement.value = value;
      document.body.appendChild(tempElement);
      tempElement.select();
      document.execCommand('copy');
      document.body.removeChild(tempElement);
      
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy text using execCommand: ', err);
      // In a production app, we would show a custom modal here.
    }
  };
  
  return (
    <div>
      <div className="flex justify-between items-center mb-1">
        <label className="text-xs font-semibold text-gray-400">{label}</label>
        <button 
          onClick={handleCopy} 
          title={copied ? "Copied!" : "Copy to Clipboard"} 
          className="text-gray-500 hover:text-white flex items-center"
        >
          {copied ? (
            <CheckCircle className="w-3 h-3 text-green-400" />
          ) : (
            <Copy className="w-3 h-3" />
          )}
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
};


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
            {/* Using updated KeyDisplay without onCopy prop */}
            <KeyDisplay label="Public Key (Base64)" value={message.publicKey} />
            <KeyDisplay label="Signature (Base64)" value={message.signature} />
          </div>
        )}
      </div>
    </div>
  );
};

/**
 * MainApplication Component
 * The core app UI shown after successful authentication.
 */
const MainApplication = ({ db, userId }) => {
  // Check for Crypto Support
  const isCryptoSupported = useMemo(() => typeof window.crypto?.subtle !== 'undefined', []);

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
  const [verificationStatus, setVerificationStatus] = useState({ id: null, status: null });
  const [postWarning, setPostWarning] = useState(null);

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
    if (!isCryptoSupported) {
        setPostWarning('Web Crypto API not supported in this browser environment.');
        setTimeout(() => setPostWarning(null), 5000);
        return;
    }

    setIsLoading(true);
    setPostWarning(null);
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
      setPostWarning('Key generation failed. Check console for details.');
      setTimeout(() => setPostWarning(null), 5000);
    }
    setIsLoading(false);
  };

  const handleSignAndPost = async () => {
    if (!newMessage || !keyPair) {
      const message = !keyPair 
        ? "Please generate a key pair first (Step 1)." 
        : "Please enter a message to sign.";
      setPostWarning(message);
      setTimeout(() => setPostWarning(null), 4000);
      return;
    }
    
    setIsPosting(true);
    setPostWarning(null); 
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
      
      setNewMessage('');
      
    } catch (err) {
      console.error("Failed to sign and post message:", err);
      setPostWarning('Failed to sign or post message. Check console for details.');
      setTimeout(() => setPostWarning(null), 5000);
    }
    setIsPosting(false);
  };
  
  const handleVerify = async (messageDoc) => {
    if (!isCryptoSupported) {
        setVerificationStatus({ id: messageDoc.id, status: 'invalid' });
        return;
    }
    
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

  if (!isCryptoSupported) {
      return (
          <div className="flex items-center justify-center h-screen bg-gray-900 p-8">
              <div className="bg-yellow-800 p-6 rounded-lg shadow-xl text-white max-w-md">
                  <h2 className="text-xl font-bold mb-3 flex items-center">
                      <AlertTriangle className="w-6 h-6 mr-2" />
                      Crypto API Not Supported
                  </h2>
                  <p className="text-sm">
                      This application requires the **Web Crypto API** for key generation and digital signing, but it is not available or supported in your current browser environment.
                  </p>
              </div>
          </div>
      );
  }

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
              {/* Using updated KeyDisplay without onCopy prop */}
              <KeyDisplay label="Your Public Key (Base64)" value={publicKeyB64} />
              <KeyDisplay label="Your Private Key (Base64)" value={privateKeyB64} />
            </div>
          </div>

          {/* Sign Message Card */}
          <div className="bg-gray-800 p-6 rounded-lg shadow-lg">
            <h2 className="text-2xl font-semibold text-gray-100 flex items-center mb-4">
              <PenSquare className="w-6 h-6 mr-3 text-cyan-400" />
              2. Sign & Post
            </h2>
            {postWarning && (
              <div className="p-3 bg-red-800 text-white rounded-md mb-4 flex items-center">
                <XCircle className="w-5 h-5 mr-2" />
                <span className="font-medium text-sm">{postWarning}</span>
              </div>
            )}
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
  const [initError, setInitError] = useState(null);

  useEffect(() => {
    try {
      if (Object.keys(firebaseConfig).length === 0) {
        const errorMsg = "Firebase configuration is missing or empty. Cannot initialize application.";
        console.error(errorMsg);
        setInitError(errorMsg);
        setIsAuthReady(true);
        return;
      }
      
      const app = initializeApp(firebaseConfig);
      const authInstance = getAuth(app);
      const dbInstance = getFirestore(app);
      
      setLogLevel('debug');

      setDb(dbInstance);
      setAuth(authInstance);

      const unsubscribe = onAuthStateChanged(authInstance, async (user) => {
        if (user) {
          setUserId(user.uid);
          setIsAuthReady(true);
        } else {
          try {
            if (initialAuthToken) {
              await signInWithCustomToken(authInstance, initialAuthToken);
            } else {
              await signInAnonymously(authInstance);
            }
          } catch (authError) {
            const errorMsg = `Authentication failed: ${authError.message}.`;
            console.error(errorMsg);
            setInitError(errorMsg);
            setIsAuthReady(true);
          }
        }
      });
      
      return () => unsubscribe();
      
    } catch (e) {
      const errorMsg = `A critical error occurred during Firebase initialization: ${e.message}`;
      console.error(errorMsg, e);
      setInitError(errorMsg);
      setIsAuthReady(true);
    }
  }, []);

  if (initError) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-900 p-8">
        <div className="bg-red-800 p-6 rounded-lg shadow-xl text-white max-w-md">
          <h2 className="text-xl font-bold mb-3 flex items-center">
            <XCircle className="w-6 h-6 mr-2" />
            Application Initialization Error
          </h2>
          <p className="text-sm">{initError}</p>
          <p className="mt-3 text-xs text-gray-200">
            Please check your console for detailed error messages related to Firebase configuration or authentication.
          </p>
        </div>
      </div>
    );
  }
  
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
