import React, { useState, useEffect, useRef } from 'react';
import { Send, User, Users, Shield, LogOut, ChevronRight, MessageCircle } from 'lucide-react';
import './index.css';

const getWsUrl = () => {
  if (import.meta.env.VITE_WS_URL) {
    return import.meta.env.VITE_WS_URL;
  }
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  if (window.location.port === '5173') {
    return 'ws://localhost:8000/ws';
  }
  return `${proto}//${window.location.host}/ws`;
};

const WS_BASE_URL = getWsUrl();

function App() {
  const [username, setUsername] = useState('');
  const [isJoined, setIsJoined] = useState(false);
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  const [messages, setMessages] = useState([]); // Array of {from, to, content, timestamp, outgoing}
  const [inputText, setInputText] = useState('');
  const [status, setStatus] = useState('Offline');
  const ws = useRef(null);
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const connect = () => {
    if (!username.trim()) return;

    ws.current = new WebSocket(`${WS_BASE_URL}/${username}`);

    ws.current.onopen = () => {
      setStatus('Online');
      setIsJoined(true);
      // Automatically request user list
      ws.current.send(JSON.stringify({ type: 'LIST' }));
    };

    ws.current.onmessage = (event) => {
      const data = JSON.parse(event.data);
      console.log('WS Message:', data);

      if (data.type === 'MESSAGE') {
        setMessages(prev => [...prev, {
          from: data.from,
          to: username,
          content: data.content,
          timestamp: data.timestamp || new Date().toISOString(),
          outgoing: false
        }]);
      } else if (data.type === 'USER_LIST') {
        setOnlineUsers(data.users.filter(u => u !== username));
      } else if (data.type === 'ACK') {
        console.log('ACK:', data.info);
      } else if (data.type === 'ERROR') {
        alert('Error: ' + data.message);
      } else if (data.type === 'STATUS') {
        console.log('Status update:', data.message);
      }
    };

    ws.current.onclose = () => {
      setStatus('Disconnected');
      setIsJoined(false);
    };

    ws.current.onerror = (err) => {
      console.error('WS Error:', err);
      setStatus('Error');
    };
  };

  const handleSendMessage = (e) => {
    e.preventDefault();
    if (!inputText.trim() || !selectedUser) return;

    const msg = {
      type: 'SEND',
      to: selectedUser,
      text: inputText
    };

    ws.current.send(JSON.stringify(msg));

    // Optimistic UI for outgoing message
    setMessages(prev => [...prev, {
      from: username,
      to: selectedUser,
      content: inputText,
      timestamp: new Date().toISOString(),
      outgoing: true
    }]);

    setInputText('');
  };

  const handleLogout = () => {
    ws.current?.close();
    setIsJoined(false);
    setMessages([]);
    setOnlineUsers([]);
    setSelectedUser(null);
  };

  const filteredMessages = messages.filter(m =>
    (m.from === selectedUser && m.to === username) ||
    (m.from === username && m.to === selectedUser)
  );

  if (!isJoined) {
    return (
      <div className="login-overlay">
        <div className="login-card">
          <Shield size={48} color="#6366f1" style={{ marginBottom: 20 }} />
          <h1>Secure Messaging</h1>
          <p style={{ color: '#94a3b8', marginBottom: 24 }}>Enter your username to connect securely.</p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && connect()}
            />
            <button onClick={connect}>Join Chat</button>
          </div>
          <p style={{ marginTop: 24, fontSize: '0.8rem', color: '#64748b' }}>
            E2E Encryption • RSA-2048 • AES-GCM
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="app-container">
      <div className="sidebar">
        <div className="sidebar-header">
          <h2><Shield size={24} /> CN-Secure</h2>
        </div>

        <div className="user-status">
          <div className="status-dot"></div>
          <div>
            <div style={{ fontSize: '0.9rem', fontWeight: 600 }}>{username}</div>
            <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>{status}</div>
          </div>
          <button
            onClick={handleLogout}
            style={{ marginLeft: 'auto', padding: '6px', background: 'transparent', color: '#94a3b8' }}
          >
            <LogOut size={18} />
          </button>
        </div>

        <div style={{ padding: '0 24px 12px', fontSize: '0.75rem', fontWeight: 600, color: '#64748b', textTransform: 'uppercase' }}>
          Online Users
        </div>

        <div className="user-list">
          {onlineUsers.length > 0 ? onlineUsers.map((user) => (
            <div
              key={user}
              className={`user-item ${selectedUser === user ? 'active' : ''}`}
              onClick={() => setSelectedUser(user)}
            >
              <div style={{ width: 32, height: 32, background: 'rgba(255,255,255,0.1)', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <User size={16} />
              </div>
              <span>{user}</span>
              {selectedUser === user && <ChevronRight size={16} style={{ marginLeft: 'auto' }} />}
            </div>
          )) : (
            <div style={{ padding: '24px', textAlign: 'center', color: '#64748b', fontSize: '0.85rem' }}>
              No other users online.
            </div>
          )}
        </div>

        <button
          onClick={() => ws.current.send(JSON.stringify({ type: 'LIST' }))}
          style={{ margin: '12px', padding: '10px', fontSize: '0.8rem', background: 'rgba(255,255,255,0.05)' }}
        >
          Refresh Users
        </button>
      </div>

      <div className="chat-main">
        {selectedUser ? (
          <>
            <div className="chat-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div style={{ width: 40, height: 40, background: 'rgba(99, 102, 241, 0.2)', color: '#6366f1', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <User size={20} />
                </div>
                <div>
                  <div style={{ fontWeight: 600 }}>{selectedUser}</div>
                  <div style={{ fontSize: '0.75rem', color: '#accent' }}>Active now</div>
                </div>
              </div>
              <div style={{ fontSize: '0.75rem', color: '#94a3b8', background: 'rgba(255,255,255,0.05)', padding: '4px 12px', borderRadius: '20px' }}>
                Encrypted Session
              </div>
            </div>

            <div className="messages-area">
              {filteredMessages.length > 0 ? filteredMessages.map((msg, i) => (
                <div key={i} className={`message-bubble ${msg.outgoing ? 'outgoing' : 'incoming'}`}>
                  <div className="message-info" style={{ color: msg.outgoing ? 'rgba(255,255,255,0.7)' : '#94a3b8' }}>
                    {msg.outgoing ? 'You' : msg.from} • {new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </div>
                  <div>{msg.content}</div>
                </div>
              )) : (
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', color: '#64748b', gap: 12 }}>
                  <MessageCircle size={48} style={{ opacity: 0.2 }} />
                  <p>Send a message to start the conversation.</p>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>

            <form className="chat-input-area" onSubmit={handleSendMessage}>
              <input
                type="text"
                placeholder={`Message @${selectedUser}...`}
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
              />
              <button type="submit">
                <Send size={18} />
                Send
              </button>
            </form>
          </>
        ) : (
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', background: 'rgba(15, 23, 42, 0.2)' }}>
            <Shield size={64} color="#1e293b" style={{ marginBottom: 24 }} />
            <h2 style={{ color: '#475569' }}>Select a user to start chatting</h2>
            <p style={{ color: '#64748b', marginTop: 8 }}>Your conversations are always end-to-end encrypted.</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
