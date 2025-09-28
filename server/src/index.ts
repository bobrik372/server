import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import multer from 'multer';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import { PrismaClient } from '@prisma/client';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import { z } from 'zod';
import { Nickname, Username, DisplayName } from '@anubis/shared';

const app = express();
app.use(cors());
app.use(express.json());

const httpServer = createServer(app);
const io = new SocketIOServer(httpServer, {
  cors: {
    origin: '*',
  },
});

const prisma = new PrismaClient();

const PORT = Number(process.env.PORT || 4000);
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const UPLOAD_DIR = process.env.UPLOAD_DIR || 'uploads';
if (!fs.existsSync(path.resolve(UPLOAD_DIR))) {
  fs.mkdirSync(path.resolve(UPLOAD_DIR), { recursive: true });
}
app.use('/media', express.static(path.resolve(UPLOAD_DIR)));

// Multer storage
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, path.resolve(UPLOAD_DIR));
  },
  filename: (_req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + '-' + file.originalname);
  },
});
const upload = multer({ storage });

// Helpers
function generatePassphrase(): string {
  const words = [
    'alpha','bravo','charlie','delta','echo','foxtrot','golf','hotel','india','juliet','kilo','lima','mike','november','oscar','papa','quebec','romeo','sierra','tango','uniform','victor','whiskey','xray','yankee','zulu'
  ];
  const pick = () => words[Math.floor(Math.random() * words.length)];
  const w = [pick(), pick(), pick(), pick(), pick()].join('-');
  const digits = Array.from({ length: 12 }, () => Math.floor(Math.random() * 10)).join('');
  return `${w}-${digits}`;
}

function signToken(username: string) {
  return jwt.sign({ sub: username }, JWT_SECRET, { expiresIn: '30d' });
}

async function authMiddleware(req: any, res: any, next: any) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'unauthorized' });
  const token = auth.replace('Bearer ', '');
  try {
    const payload = jwt.verify(token, JWT_SECRET) as any;
    const user = await prisma.user.findUnique({ where: { username: payload.sub } });
    if (!user) return res.status(401).json({ error: 'unauthorized' });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'unauthorized' });
  }
}

function derivePassKey(passphrase: string) {
  const pepper = process.env.JWT_SECRET || 'dev-secret';
  return crypto.createHmac('sha256', pepper).update(passphrase).digest('hex');
}

// Auth
app.post('/api/auth/register', async (req, res) => {
  const passphrase = generatePassphrase();
  // Create a placeholder user with random username; client should set later
  let username: string;
  for (;;) {
    username = 'u' + Math.random().toString(36).slice(2, 10);
    const exists = await prisma.user.findUnique({ where: { username } });
    if (!exists) break;
  }
  const passhash = await argon2.hash(passphrase);
  const passKey = derivePassKey(passphrase);
  const user = await prisma.user.create({
    data: {
      username,
      displayName: 'New User',
      nickname: '!newuser',
      avatarUrl: null,
      passhash,
      passKey,
      settings: JSON.stringify({ theme: 'light', fontScale: 1, language: 'ru' }),
    },
  });
  res.json({ passphrase });
});

app.post('/api/auth/login', async (req, res) => {
  const body = z.object({ passphrase: z.string() }).safeParse(req.body);
  if (!body.success) return res.status(400).json({ error: 'invalid' });
  const passKey = derivePassKey(body.data.passphrase);
  const user = await prisma.user.findUnique({ where: { passKey } });
  if (!user) return res.status(401).json({ error: 'unauthorized' });
  const ok = await argon2.verify(user.passhash, body.data.passphrase);
  if (!ok) return res.status(401).json({ error: 'unauthorized' });
  const token = signToken(user.username);
  return res.json({
    accessToken: token,
    user: {
      username: user.username,
      displayName: user.displayName,
      nickname: user.nickname,
      avatarUrl: user.avatarUrl ?? null,
    },
  });
});

// Profile update (username/displayName/nickname/avatar)
app.put('/api/me', authMiddleware, upload.single('avatar'), async (req: any, res) => {
  const body = z.object({
    username: Username.optional(),
    displayName: DisplayName.optional(),
    nickname: Nickname.optional(),
  }).safeParse(req.body);
  if (!body.success) return res.status(400).json({ error: 'invalid' });

  // avatar
  let avatarUrl: string | undefined;
  if (req.file) {
    avatarUrl = `/media/${req.file.filename}`;
  }

  try {
    const updated = await prisma.user.update({
      where: { id: req.user.id },
      data: {
        username: body.data.username ?? undefined,
        displayName: body.data.displayName ?? undefined,
        nickname: body.data.nickname ?? undefined,
        avatarUrl: avatarUrl ?? undefined,
      },
    });
    res.json({
      username: updated.username,
      displayName: updated.displayName,
      nickname: updated.nickname,
      avatarUrl: updated.avatarUrl ?? null,
    });
  } catch (e: any) {
    if (e.code === 'P2002') return res.status(409).json({ error: 'username_taken' });
    return res.status(500).json({ error: 'server_error' });
  }
});

// Change passphrase
app.post('/api/me/change-password', authMiddleware, async (req: any, res) => {
  const body = z.object({ currentPassphrase: z.string(), newPassphrase: z.string() }).safeParse(req.body);
  if (!body.success) return res.status(400).json({ error: 'invalid' });
  const ok = await argon2.verify(req.user.passhash, body.data.currentPassphrase);
  if (!ok) return res.status(403).json({ error: 'wrong_password' });
  const passhash = await argon2.hash(body.data.newPassphrase);
  const passKey = derivePassKey(body.data.newPassphrase);
  await prisma.user.update({ where: { id: req.user.id }, data: { passhash, passKey } });
  res.json({ ok: true });
});

// Search by nickname or username
app.get('/api/search', authMiddleware, async (req: any, res) => {
  const q = String(req.query.q || '');
  const users = await prisma.user.findMany({
    where: q.startsWith('!') ? { nickname: q } : { username: q },
    select: { username: true, displayName: true, nickname: true, avatarUrl: true },
    take: 20,
  });
  res.json(users);
});

// Block / unblock
app.post('/api/block', authMiddleware, async (req: any, res) => {
  const body = z.object({ username: Username }).safeParse(req.body);
  if (!body.success) return res.status(400).json({ error: 'invalid' });
  const target = await prisma.user.findUnique({ where: { username: body.data.username } });
  if (!target) return res.status(404).json({ error: 'not_found' });
  if (target.id === req.user.id) return res.status(400).json({ error: 'cant_block_self' });
  await prisma.block.upsert({
    where: { blockerId_blockedId: { blockerId: req.user.id, blockedId: target.id } },
    update: {},
    create: { blockerId: req.user.id, blockedId: target.id },
  });
  res.json({ ok: true });
});

app.post('/api/unblock', authMiddleware, async (req: any, res) => {
  const body = z.object({ username: Username }).safeParse(req.body);
  if (!body.success) return res.status(400).json({ error: 'invalid' });
  const target = await prisma.user.findUnique({ where: { username: body.data.username } });
  if (!target) return res.status(404).json({ error: 'not_found' });
  await prisma.block.deleteMany({ where: { blockerId: req.user.id, blockedId: target.id } });
  res.json({ ok: true });
});

// Upload media
app.post('/api/upload', authMiddleware, upload.single('file'), async (req: any, res) => {
  if (!req.file) return res.status(400).json({ error: 'no_file' });
  const url = `/media/${req.file.filename}`;
  res.json({ mediaUrl: url });
});

// Simple message send via REST + WS notify
app.post('/api/messages', authMiddleware, async (req: any, res) => {
  const body = z.object({
    to: Username,
    type: z.enum(['text', 'image', 'video', 'audio']),
    text: z.string().optional(),
    mediaUrl: z.string().optional(),
  }).safeParse(req.body);
  if (!body.success) return res.status(400).json({ error: 'invalid' });
  const recipient = await prisma.user.findUnique({ where: { username: body.data.to } });
  if (!recipient) return res.status(404).json({ error: 'not_found' });
  const blocked = await prisma.block.findFirst({ where: {
    OR: [
      { blockerId: req.user.id, blockedId: recipient.id },
      { blockerId: recipient.id, blockedId: req.user.id },
    ]
  }});
  if (blocked) return res.status(403).json({ error: 'blocked' });

  const chatId = [req.user.id, recipient.id].sort().join('-');
  const msg = await prisma.message.create({
    data: {
      chatId,
      type: body.data.type,
      text: body.data.text,
      mediaUrl: body.data.mediaUrl,
      senderId: req.user.id,
      recipientId: recipient.id,
    }
  });
  const payload = {
    id: msg.id,
    chatId: msg.chatId,
    type: msg.type,
    text: msg.text,
    mediaUrl: msg.mediaUrl,
    createdAt: msg.createdAt,
    senderUsername: req.user.username,
    recipientUsername: recipient.username,
  } as const;
  io.to(recipient.username).emit('message', payload);
  res.json(payload);
});

io.on('connection', (socket) => {
  // authenticate via query token
  const token = socket.handshake.auth?.token as string | undefined;
  if (!token) return socket.disconnect(true);
  try {
    const payload = jwt.verify(token, JWT_SECRET) as any;
    const username = payload.sub as string;
    socket.join(username);
    socket.emit('presence', { me: username, status: 'online' });
    socket.on('typing', (to: string) => {
      io.to(to).emit('typing', { from: username });
    });
    socket.on('disconnect', () => {
      // presence offline can be broadcast if needed
    });
  } catch {
    socket.disconnect(true);
  }
});

httpServer.listen(PORT, () => {
  console.log(`Anubis server listening on :${PORT}`);
});
