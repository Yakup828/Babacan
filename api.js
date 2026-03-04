// routes/api.js — Messages + Support + Admin
const router = require('express').Router();
const bcrypt = require('bcrypt');
const { requireAuth, requireAdmin, addScore } = require('../middleware/security');
const { DB, audit, publicUser, adminUser, findUser } = require('../utils/database');
const { sanitizeStr, generateUID } = require('../utils/security');
const { validateUsername, validatePassword } = require('../utils/validators');

const SALT_ROUNDS = 12;

// ══════════════════════════════════════════════════════════════════════════
// MESSAGES
// ══════════════════════════════════════════════════════════════════════════

// GET /api/messages
router.get('/messages', requireAuth, (req, res) => {
  res.json(DB.msgs);
});

// POST /api/messages
router.post('/messages', requireAuth, (req, res) => {
  let { text, time, replyTo } = req.body;

  if (!text || typeof text !== 'string') return res.status(400).json({ success: false });
  if (text.length > 5000) return res.status(400).json({ success: false, error: 'Message too long' });

  const user = findUser(req.user.uid) || (req.user.uid === global.ADMIN?.uid ? global.ADMIN : null);
  if (!user) return res.status(401).json({ success: false });

  text = sanitizeStr(text, 5000);

  // replyTo doğrulaması
  const safeReplyTo = (Number.isInteger(replyTo) && replyTo >= 0 && replyTo < DB.msgs.length)
    ? replyTo : undefined;

  const msg = {
    uid:     req.user.uid,
    name:    sanitizeStr(user.name, 50),
    text,
    time:    sanitizeStr(String(time || ''), 10),
    replyTo: safeReplyTo,
  };

  DB.msgs.push(msg);

  // Mesaj limiti (bellek koruması)
  if (DB.msgs.length > 5000) DB.msgs.shift();

  return res.status(201).json({ success: true, msg });
});

// DELETE /api/messages/:idx — Kendi mesajını veya admin tümünü silebilir
router.delete('/messages/:idx', requireAuth, (req, res) => {
  const idx = parseInt(req.params.idx);
  if (isNaN(idx) || idx < 0 || idx >= DB.msgs.length) {
    return res.status(404).json({ success: false });
  }

  const msg = DB.msgs[idx];
  if (msg.uid !== req.user.uid && !req.user.admin) {
    addScore(req.ip, 5);
    audit('UNAUTHORIZED_DELETE', req.ip, req.user.uid);
    return res.status(403).json({ success: false, error: 'Forbidden' });
  }

  DB.msgs.splice(idx, 1);
  return res.json({ success: true });
});

// ══════════════════════════════════════════════════════════════════════════
// SUPPORT
// ══════════════════════════════════════════════════════════════════════════

const SUPPORT_TYPES = ['req', 'sup', 'com'];

router.post('/support', requireAuth, (req, res) => {
  const { type, msg } = req.body;

  if (!type || !msg || typeof msg !== 'string') return res.status(400).json({ success: false });
  if (!SUPPORT_TYPES.includes(type)) return res.status(400).json({ success: false });
  if (msg.length < 10 || msg.length > 2000) return res.status(400).json({ success: false, error: 'Message length invalid' });

  const user = findUser(req.user.uid);
  const typeNames = { req: 'İstek', sup: 'Destek', com: 'Şikayet' };

  DB.tickets.push({
    type,
    typeName: typeNames[type],
    msg: sanitizeStr(msg, 2000),
    uid:  req.user.uid,
    name: sanitizeStr(user?.name || req.user.username, 50),
    date: new Date().toISOString(),
  });

  return res.status(201).json({ success: true });
});

// ══════════════════════════════════════════════════════════════════════════
// ADMIN
// ══════════════════════════════════════════════════════════════════════════

// Admin config (public — sadece isim, şifre yok)
router.get('/admin-config', (req, res) => {
  if (!global.ADMIN) return res.status(503).json({});
  return res.json({ name: global.ADMIN.name, username: global.ADMIN.username });
});

// GET /api/admin/tickets
router.get('/admin/tickets', requireAuth, requireAdmin, (req, res) => {
  res.json(DB.tickets);
});

// GET /api/admin/users
router.get('/admin/users', requireAuth, requireAdmin, (req, res) => {
  res.json(DB.users.map(u => adminUser(u)));
});

// GET /api/admin/audit — Güvenlik log'ları
router.get('/admin/audit', requireAuth, requireAdmin, (req, res) => {
  // Son 500 log
  res.json(DB.audit.slice(-500).reverse());
});

// POST /api/admin/premium — Premium ver
router.post('/admin/premium', requireAuth, requireAdmin, (req, res) => {
  const { ident } = req.body;
  if (!ident || typeof ident !== 'string') return res.status(400).json({ success: false });

  const user = DB.users.find(u =>
    u.uid === ident || u.username.toLowerCase() === ident.toLowerCase()
  );
  if (!user) return res.status(404).json({ success: false, error: 'User not found' });

  user.premium = true;
  DB.msgs.push({
    system: true, type: 'prem',
    text: `— ${sanitizeStr(user.name, 50)} Premiuma Yükseldi 👑 —`,
    uid: '', name: '',
  });

  audit('GRANT_PREMIUM', req.ip, req.user.uid, { target: user.uid });
  return res.json({ success: true, user: publicUser(user) });
});

// PUT /api/admin/users/:uid — Kullanıcı düzenle
router.put('/admin/users/:uid', requireAuth, requireAdmin, async (req, res) => {
  const user = DB.users.find(u => u.uid === req.params.uid);
  if (!user) return res.status(404).json({ success: false });

  const { name, username, password, premium } = req.body;

  if (name && typeof name === 'string' && name.length >= 2 && name.length <= 50) {
    user.name = sanitizeStr(name, 50);
  }
  if (username && validateUsername(username)) {
    user.username = sanitizeStr(username, 30);
  }
  if (password && validatePassword(password)) {
    user.passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
  }
  if (typeof premium === 'boolean') {
    user.premium = premium;
  }

  audit('ADMIN_EDIT_USER', req.ip, req.user.uid, { target: user.uid });
  return res.json({ success: true, user: adminUser(user) });
});

// DELETE /api/admin/users/:uid — Kullanıcı sil
router.delete('/admin/users/:uid', requireAuth, requireAdmin, (req, res) => {
  const idx = DB.users.findIndex(u => u.uid === req.params.uid);
  if (idx === -1) return res.status(404).json({ success: false });

  const [removed] = DB.users.splice(idx, 1);

  // Session'ı da geçersiz kıl
  DB.sessions.delete(removed.uid);

  DB.msgs.push({
    system: true, type: 'del',
    text: `— @${sanitizeStr(removed.username, 30)} hesabı kaldırıldı —`,
    uid: '', name: '',
  });

  audit('ADMIN_DELETE_USER', req.ip, req.user.uid, { target: removed.uid, username: removed.username });
  return res.json({ success: true });
});

module.exports = router;
