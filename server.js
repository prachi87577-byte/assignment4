require('dotenv').config();
const http = require('http');
const path = require('path');
const EventEmitter = require('events');
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---------- In-memory store (swap for MongoDB if preferred) ----------
const users = [];   // { id, username, password, role }
const notes = [];   // { id, userId, title, content }
let uid = 1, nid = 1;

// ---------- EventEmitter (event-driven features) ----------
const bus = new EventEmitter();
bus.on('user:signup', u => console.log(`[EVENT] New user registered: ${u.username}`));
bus.on('user:login', u => console.log(`[EVENT] User logged in: ${u.username}`));
bus.on('note:created', n => console.log(`[EVENT] Note #${n.id} created by user ${n.userId}`));
bus.on('note:deleted', n => console.log(`[EVENT] Note #${n.id} deleted`));

// ---------- Auth helpers / middleware ----------
const sign = u => jwt.sign({ id: u.id, username: u.username, role: u.role },
  process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '1h' });

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Token missing' });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid or expired token' }); }
}
const allow = (...roles) => (req, res, next) =>
  roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'Forbidden: insufficient role' });

// ---------- Auth routes ----------
app.post('/api/signup', async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (users.find(u => u.username === username)) return res.status(409).json({ error: 'User already exists' });
  const user = { id: uid++, username, password: await bcrypt.hash(password, 10),
                 role: role === 'admin' ? 'admin' : 'user' };
  users.push(user);
  bus.emit('user:signup', user);
  res.status(201).json({ message: 'Signup successful', user: { id: user.id, username, role: user.role } });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: 'Invalid credentials' });
  bus.emit('user:login', user);
  res.json({ message: 'Login successful', token: sign(user) });
});

// ---------- Protected routes ----------
app.get('/api/profile', auth, (req, res) => res.json({ user: req.user }));
app.get('/api/admin/users', auth, allow('admin'), (req, res) =>
  res.json(users.map(({ password, ...u }) => u)));

// ---------- Notes API (CRUD, owner-scoped) ----------
app.post('/api/notes', auth, (req, res) => {
  const { title, content } = req.body;
  if (!title) return res.status(400).json({ error: 'title required' });
  const note = { id: nid++, userId: req.user.id, title, content: content || '' };
  notes.push(note);
  bus.emit('note:created', note);
  res.status(201).json(note);
});
app.get('/api/notes', auth, (req, res) =>
  res.json(notes.filter(n => n.userId === req.user.id)));
app.get('/api/notes/:id', auth, (req, res) => {
  const n = notes.find(x => x.id == req.params.id && x.userId === req.user.id);
  n ? res.json(n) : res.status(404).json({ error: 'Note not found' });
});
app.put('/api/notes/:id', auth, (req, res) => {
  const n = notes.find(x => x.id == req.params.id && x.userId === req.user.id);
  if (!n) return res.status(404).json({ error: 'Note not found' });
  n.title = req.body.title ?? n.title;
  n.content = req.body.content ?? n.content;
  res.json(n);
});
app.delete('/api/notes/:id', auth, (req, res) => {
  const i = notes.findIndex(x => x.id == req.params.id && x.userId === req.user.id);
  if (i === -1) return res.status(404).json({ error: 'Note not found' });
  bus.emit('note:deleted', notes.splice(i, 1)[0]);
  res.json({ message: 'Note deleted' });
});

// ---------- Socket.IO (JWT-secured real-time chat) ----------
io.use((socket, next) => {
  try { socket.user = jwt.verify(socket.handshake.auth.token, process.env.JWT_SECRET); next(); }
  catch { next(new Error('Authentication error')); }
});
io.on('connection', socket => {
  console.log(`[CHAT] ${socket.user.username} connected`);
  io.emit('system', `${socket.user.username} joined the chat`);
  socket.on('chat:message', text => {
    const msg = { from: socket.user.username, text, time: new Date().toISOString() };
    console.log(`[CHAT] ${msg.from}: ${text}`);
    io.emit('chat:message', msg);
  });
  socket.on('disconnect', () => {
    console.log(`[CHAT] ${socket.user.username} disconnected`);
    io.emit('system', `${socket.user.username} left the chat`);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
