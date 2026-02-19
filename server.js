const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const WebSocket = require('ws');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
const server = http.createServer(app);

// ==================== SUPABASE SETUP ====================
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY // Gunakan Service Role Key (bukan anon key)
);

// ==================== UPLOAD SETUP ====================
const uploadDir = './uploads';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, 'dokumentasi-' + uniqueSuffix + ext);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif|webp/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);
  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb(new Error('Hanya file gambar yang diperbolehkan (jpg, jpeg, png, gif, webp)'));
  }
};

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: fileFilter
});

const JWT_SECRET = process.env.JWT_SECRET || 'zhafran_trans_secret_key_2025';
const PORT = process.env.PORT || 5000;

// ==================== WEBSOCKET SETUP ====================
const wss = new WebSocket.Server({
  server,
  path: '/',
  verifyClient: (info) => {
    console.log('WebSocket connection attempt from:', info.origin);
    return true;
  }
});

// ==================== MIDDLEWARE ====================
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());

// ==================== INIT DATABASE ====================
async function initDatabase() {
  try {
    // Buat tabel users jika belum ada
    const { error: usersError } = await supabase.rpc('exec_sql', {
      sql: `
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          nama TEXT NOT NULL,
          no_telp TEXT NOT NULL UNIQUE,
          password TEXT NOT NULL,
          role TEXT NOT NULL CHECK(role IN ('admin', 'kurir')),
          last_seen TIMESTAMPTZ DEFAULT NOW(),
          is_online INTEGER DEFAULT 0,
          created_at TIMESTAMPTZ DEFAULT NOW()
        );
      `
    });

    // Buat tabel pengiriman
    await supabase.rpc('exec_sql', {
      sql: `
        CREATE TABLE IF NOT EXISTS pengiriman (
          id SERIAL PRIMARY KEY,
          no_resi TEXT UNIQUE,
          nama_pengirim TEXT,
          no_telp_pengirim TEXT,
          alamat_asal TEXT,
          nama_penerima TEXT,
          no_telp_penerima TEXT,
          alamat_tujuan TEXT,
          nama_barang TEXT,
          jenis_barang TEXT,
          jumlah_barang INTEGER DEFAULT 1,
          berat REAL,
          biaya_pengiriman REAL,
          status TEXT DEFAULT 'dalamproses',
          tanggal TEXT,
          no_pol_armada TEXT DEFAULT '-',
          nama_kurir TEXT DEFAULT '-'
        );
      `
    });

    // Buat tabel status_pengiriman
    await supabase.rpc('exec_sql', {
      sql: `
        CREATE TABLE IF NOT EXISTS status_pengiriman (
          id SERIAL PRIMARY KEY,
          no_resi TEXT NOT NULL REFERENCES pengiriman(no_resi),
          status TEXT NOT NULL,
          lokasi TEXT,
          keterangan TEXT,
          dokumentasi TEXT,
          tanggal TIMESTAMPTZ DEFAULT NOW(),
          created_at TIMESTAMPTZ DEFAULT NOW()
        );
      `
    });

    console.log('✅ Database tables ready');
    await createDefaultAdmin();
  } catch (err) {
    console.error('❌ Error initializing database:', err);
    // Lanjutkan meski error — tabel mungkin sudah ada
    await createDefaultAdmin();
  }
}

async function createDefaultAdmin() {
  const { data: existing } = await supabase
    .from('users')
    .select('id')
    .eq('role', 'admin')
    .limit(1)
    .single();

  if (!existing) {
    const hashedPassword = await bcrypt.hash('admin123', 10);
    const { error } = await supabase.from('users').insert([{
      nama: 'Admin',
      no_telp: '081234567890',
      password: hashedPassword,
      role: 'admin'
    }]);
    if (error) console.error('❌ Error creating default admin:', error);
    else console.log('✅ Default admin created');
  }
}

initDatabase();

// ==================== JWT MIDDLEWARE ====================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token tidak ditemukan' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token tidak valid' });
    req.user = user;
    next();
  });
};

// ==================== WEBSOCKET ====================
const clients = new Map();

wss.on('connection', (ws, req) => {
  let authTimeout = setTimeout(() => {
    if (!ws.userId) ws.close();
  }, 5000);

  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      if (data.type === 'authenticate') {
        jwt.verify(data.token, JWT_SECRET, async (err, decoded) => {
          if (!err) {
            clearTimeout(authTimeout);
            ws.userId = decoded.userId;

            const oldWs = clients.get(decoded.userId);
            if (oldWs && oldWs !== ws) oldWs.close();

            clients.set(decoded.userId, ws);
            await updateUserStatus(decoded.userId, 1);
            broadcastOnlineUsers();
            ws.send(JSON.stringify({ type: 'authenticated', userId: decoded.userId }));
          } else {
            clearTimeout(authTimeout);
            ws.close();
          }
        });
      }
    } catch (err) {
      console.error('WebSocket message error:', err);
    }
  });

  ws.on('close', async () => {
    clearTimeout(authTimeout);
    if (ws.userId) {
      clients.delete(ws.userId);
      await updateUserStatus(ws.userId, 0);
      broadcastOnlineUsers();
    }
  });

  ws.on('error', () => clearTimeout(authTimeout));
});

const heartbeatInterval = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);
wss.on('close', () => clearInterval(heartbeatInterval));

async function updateUserStatus(userId, isOnline) {
  const { error } = await supabase
    .from('users')
    .update({ is_online: isOnline, last_seen: new Date().toISOString() })
    .eq('id', userId);
  if (error) console.error('Error updating user status:', error);
}

async function broadcastOnlineUsers() {
  const { data: users, error } = await supabase
    .from('users')
    .select('id, nama, no_telp, role, is_online, last_seen');
  if (error) return console.error('Error fetching users:', error);

  const message = JSON.stringify({ type: 'online_users', users });
  clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) client.send(message);
  });
}

// ==================== ROUTES ====================

// Health check
app.get('/api/health', (req, res) =>
  res.json({ status: 'OK', message: 'Zhafran Trans API is running (Supabase)' })
);

// Login
app.post('/api/login', async (req, res) => {
  const { no_telp, password } = req.body;
  if (!no_telp || !password)
    return res.status(400).json({ message: 'No telepon dan password harus diisi' });

  const { data: user, error } = await supabase
    .from('users')
    .select('*')
    .eq('no_telp', no_telp)
    .single();

  if (error || !user)
    return res.status(401).json({ message: 'No telepon atau password salah' });

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword)
    return res.status(401).json({ message: 'No telepon atau password salah' });

  const token = jwt.sign(
    { userId: user.id, role: user.role, nama: user.nama },
    JWT_SECRET,
    { expiresIn: '24h' }
  );

  await supabase.from('users').update({ last_seen: new Date().toISOString() }).eq('id', user.id);

  res.json({
    message: 'Login berhasil',
    token,
    user: { id: user.id, nama: user.nama, no_telp: user.no_telp, role: user.role }
  });
});

// Logout
app.post('/api/logout', authenticateToken, async (req, res) => {
  try {
    await supabase
      .from('users')
      .update({ is_online: 0, last_seen: new Date().toISOString() })
      .eq('id', req.user.userId);

    const ws = clients.get(req.user.userId);
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.close(1000, 'User logged out');
      clients.delete(req.user.userId);
    }

    broadcastOnlineUsers();
    res.json({ message: 'Logout berhasil' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Register (admin only)
app.post('/api/register', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin')
    return res.status(403).json({ message: 'Hanya admin yang dapat mendaftarkan user baru' });

  const { nama, no_telp, password, role } = req.body;
  if (!nama || !no_telp || !password || !role)
    return res.status(400).json({ message: 'Semua field harus diisi' });
  if (!['admin', 'kurir'].includes(role))
    return res.status(400).json({ message: 'Role harus admin atau kurir' });

  const { data: existing } = await supabase
    .from('users')
    .select('id')
    .eq('no_telp', no_telp)
    .single();

  if (existing) return res.status(400).json({ message: 'No telepon sudah terdaftar' });

  const hashedPassword = await bcrypt.hash(password, 10);
  const { data, error } = await supabase
    .from('users')
    .insert([{ nama, no_telp, password: hashedPassword, role }])
    .select()
    .single();

  if (error) return res.status(500).json({ message: 'Error saat mendaftarkan user' });

  res.status(201).json({
    message: 'User berhasil didaftarkan',
    user: { id: data.id, nama, no_telp, role }
  });
});

// Get all users
app.get('/api/users', authenticateToken, async (req, res) => {
  const { role } = req.query;

  let query = supabase
    .from('users')
    .select('id, nama, no_telp, role, is_online, last_seen, created_at')
    .order('is_online', { ascending: false })
    .order('last_seen', { ascending: false });

  if (role) query = query.eq('role', role);

  const { data, error } = await query;
  if (error) return res.status(500).json({ message: 'Gagal mengambil data users' });

  res.json({ success: true, data, users: data });
});

// Get profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  const { data: user, error } = await supabase
    .from('users')
    .select('id, nama, no_telp, role, is_online, last_seen')
    .eq('id', req.user.userId)
    .single();

  if (error || !user) return res.status(404).json({ message: 'User tidak ditemukan' });
  res.json({ user });
});

// Update user (admin only)
app.put('/api/users/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin')
    return res.status(403).json({ message: 'Hanya admin yang dapat mengupdate user' });

  const { id } = req.params;
  const { nama, no_telp, password, role } = req.body;

  if (!nama || !no_telp || !role)
    return res.status(400).json({ message: 'Nama, no telepon, dan role harus diisi' });
  if (!['admin', 'kurir'].includes(role))
    return res.status(400).json({ message: 'Role harus admin atau kurir' });

  const { data: existing } = await supabase
    .from('users')
    .select('id')
    .eq('no_telp', no_telp)
    .neq('id', id)
    .single();

  if (existing) return res.status(400).json({ message: 'No telepon sudah digunakan user lain' });

  let updateData = { nama, no_telp, role };
  if (password && password.trim() !== '') {
    updateData.password = await bcrypt.hash(password, 10);
  }

  const { error } = await supabase.from('users').update(updateData).eq('id', id);
  if (error) return res.status(500).json({ message: 'Error saat mengupdate user' });

  res.json({ message: 'User berhasil diupdate', user: { id, nama, no_telp, role } });
});

// Delete user (admin only)
app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin')
    return res.status(403).json({ message: 'Hanya admin yang dapat menghapus user' });

  const { id } = req.params;
  if (parseInt(id) === req.user.userId)
    return res.status(400).json({ message: 'Tidak dapat menghapus akun sendiri' });

  const { error } = await supabase.from('users').delete().eq('id', id);
  if (error) return res.status(500).json({ message: 'Error saat menghapus user' });

  const ws = clients.get(parseInt(id));
  if (ws && ws.readyState === 1) {
    ws.close(1000, 'User deleted');
    clients.delete(parseInt(id));
  }

  broadcastOnlineUsers();
  res.json({ message: 'User berhasil dihapus' });
});

// ==================== PENGIRIMAN ====================

// GET list pengiriman
app.get('/api/pengiriman', authenticateToken, async (req, res) => {
  let query = supabase.from('pengiriman').select('*').order('tanggal', { ascending: false });

  if (req.query.search) {
    const s = req.query.search;
    query = query.or(`no_resi.ilike.%${s}%,nama_pengirim.ilike.%${s}%,nama_penerima.ilike.%${s}%`);
  }
  if (req.query.status) {
    query = query.eq('status', req.query.status);
  }

  const { data, error } = await query;
  if (error) return res.status(500).json({ message: 'Gagal mengambil data', error: error.message });
  res.json({ data });
});

// GET detail by id
app.get('/api/pengiriman/:id', authenticateToken, async (req, res) => {
  const { data, error } = await supabase
    .from('pengiriman')
    .select('*')
    .eq('id', req.params.id)
    .single();

  if (error || !data) return res.status(404).json({ message: 'Data tidak ditemukan' });
  res.json({ data });
});

// POST create pengiriman
app.post('/api/pengiriman', authenticateToken, async (req, res) => {
  const d = req.body;
  const { data, error } = await supabase.from('pengiriman').insert([{
    no_resi: d.no_resi,
    nama_pengirim: d.nama_pengirim,
    no_telp_pengirim: d.no_telp_pengirim,
    alamat_asal: d.alamat_asal,
    nama_penerima: d.nama_penerima,
    no_telp_penerima: d.no_telp_penerima,
    alamat_tujuan: d.alamat_tujuan,
    nama_barang: d.nama_barang,
    jenis_barang: d.jenis_barang,
    jumlah_barang: d.jumlah_barang || 1,
    berat: d.berat,
    biaya_pengiriman: d.biaya_pengiriman,
    status: d.status || 'dalamproses',
    tanggal: d.tanggal,
    no_pol_armada: d.no_pol_armada || '-',
    nama_kurir: d.nama_kurir || '-'
  }]).select().single();

  if (error) return res.status(500).json({ message: 'Gagal menambahkan data', error: error.message });
  res.json({ message: 'Data pengiriman berhasil ditambahkan', id: data.id });
});

// PUT update pengiriman
app.put('/api/pengiriman/:id', authenticateToken, async (req, res) => {
  const d = req.body;
  const { error } = await supabase.from('pengiriman').update({
    no_resi: d.no_resi,
    nama_pengirim: d.nama_pengirim,
    no_telp_pengirim: d.no_telp_pengirim,
    alamat_asal: d.alamat_asal,
    nama_penerima: d.nama_penerima,
    no_telp_penerima: d.no_telp_penerima,
    alamat_tujuan: d.alamat_tujuan,
    nama_barang: d.nama_barang,
    jenis_barang: d.jenis_barang,
    jumlah_barang: d.jumlah_barang,
    berat: d.berat,
    biaya_pengiriman: d.biaya_pengiriman,
    status: d.status,
    tanggal: d.tanggal,
    no_pol_armada: d.no_pol_armada,
    nama_kurir: d.nama_kurir
  }).eq('id', req.params.id);

  if (error) return res.status(500).json({ message: 'Gagal update data', error: error.message });
  res.json({ message: 'Data pengiriman berhasil diupdate' });
});

// DELETE pengiriman
app.delete('/api/pengiriman/:id', authenticateToken, async (req, res) => {
  const { error } = await supabase.from('pengiriman').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ message: 'Gagal menghapus data', error: error.message });
  res.json({ message: 'Data pengiriman berhasil dihapus' });
});

// ==================== STATUS PENGIRIMAN ====================

// GET status history by no_resi
app.get('/api/status-pengiriman/:no_resi', authenticateToken, async (req, res) => {
  const { data, error } = await supabase
    .from('status_pengiriman')
    .select('*')
    .eq('no_resi', req.params.no_resi)
    .order('tanggal', { ascending: false });

  if (error) return res.status(500).json({ message: 'Error database', error: error.message });
  res.json({ data });
});

// POST tambah status pengiriman
app.post('/api/status-pengiriman', authenticateToken, upload.single('dokumentasi'), async (req, res) => {
  const { no_resi, status, lokasi, keterangan, tanggal } = req.body;

  if (!no_resi || !status) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.status(400).json({ message: 'No resi dan status harus diisi' });
  }

  // Validasi no_resi ada
  const { data: pengiriman } = await supabase
    .from('pengiriman')
    .select('no_resi')
    .eq('no_resi', no_resi)
    .single();

  if (!pengiriman) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.status(404).json({ message: 'Nomor resi tidak ditemukan' });
  }

  // Upload file ke Supabase Storage (jika ada file)
  let dokumentasiUrl = null;
  if (req.file) {
    const fileBuffer = fs.readFileSync(req.file.path);
    const fileName = req.file.filename;
    const { error: uploadError } = await supabase.storage
      .from('dokumentasi') // nama bucket di Supabase Storage
      .upload(fileName, fileBuffer, {
        contentType: req.file.mimetype,
        upsert: false
      });

    if (uploadError) {
      console.error('Error upload to Supabase Storage:', uploadError);
      // Fallback: simpan file lokal
      dokumentasiUrl = `/uploads/${fileName}`;
    } else {
      // Dapatkan public URL
      const { data: urlData } = supabase.storage
        .from('dokumentasi')
        .getPublicUrl(fileName);
      dokumentasiUrl = urlData.publicUrl;
      // Hapus file lokal setelah upload ke Supabase Storage
      fs.unlinkSync(req.file.path);
    }
  }

  // Insert status baru
  const { data: newStatus, error: insertError } = await supabase
    .from('status_pengiriman')
    .insert([{
      no_resi,
      status,
      lokasi: lokasi || null,
      keterangan: keterangan || null,
      dokumentasi: dokumentasiUrl,
      tanggal: tanggal || new Date().toISOString()
    }])
    .select()
    .single();

  if (insertError) {
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    return res.status(500).json({ message: 'Gagal menambahkan status', error: insertError.message });
  }

  // Update status di tabel pengiriman
  await supabase.from('pengiriman').update({ status }).eq('no_resi', no_resi);

  // Broadcast via WebSocket
  try {
    clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({ type: 'status-updated', no_resi, status }));
      }
    });
  } catch (wsError) {
    console.error('WebSocket error:', wsError);
  }

  res.status(201).json({
    message: 'Status pengiriman berhasil ditambahkan dan diupdate',
    id: newStatus.id,
    no_resi,
    status,
    dokumentasi: dokumentasiUrl
  });
});

// DELETE status pengiriman
app.delete('/api/status-pengiriman/delete/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  const { data: statusData, error: fetchError } = await supabase
    .from('status_pengiriman')
    .select('*')
    .eq('id', id)
    .single();

  if (fetchError || !statusData)
    return res.status(404).json({ success: false, message: 'Status pengiriman tidak ditemukan' });

  const noResi = statusData.no_resi;

  // Hapus file dari Supabase Storage jika ada
  if (statusData.dokumentasi) {
    try {
      // Jika URL dari Supabase Storage, ekstrak nama file
      const isSupabaseUrl = statusData.dokumentasi.includes('supabase');
      if (isSupabaseUrl) {
        const fileName = statusData.dokumentasi.split('/').pop();
        await supabase.storage.from('dokumentasi').remove([fileName]);
      } else {
        // File lokal
        const fileName = statusData.dokumentasi.replace('/uploads/', '');
        const filePath = path.join(__dirname, 'uploads', fileName);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      }
    } catch (fileError) {
      console.error('Error deleting file:', fileError);
    }
  }

  // Hapus dari database
  await supabase.from('status_pengiriman').delete().eq('id', id);

  // Update status pengiriman berdasarkan status terakhir yang tersisa
  const { data: latestStatus } = await supabase
    .from('status_pengiriman')
    .select('status')
    .eq('no_resi', noResi)
    .order('tanggal', { ascending: false })
    .limit(1)
    .single();

  const newStatus = latestStatus ? latestStatus.status : 'dalamproses';
  await supabase.from('pengiriman').update({ status: newStatus }).eq('no_resi', noResi);

  // Broadcast WebSocket
  try {
    clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({ type: 'status-deleted', id, no_resi: noResi }));
      }
    });
  } catch (wsError) {
    console.error('WebSocket error:', wsError);
  }

  res.json({ success: true, message: 'Status pengiriman berhasil dihapus' });
});

// ==================== PUBLIC TRACKING ====================

// Public tracking by no_resi
app.get('/api/public/tracking/:no_resi', async (req, res) => {
  const { no_resi } = req.params;

  const { data: pengiriman, error } = await supabase
    .from('pengiriman')
    .select('*')
    .eq('no_resi', no_resi)
    .single();

  if (error || !pengiriman)
    return res.status(404).json({ message: 'Nomor resi tidak ditemukan' });

  const { data: statusHistory } = await supabase
    .from('status_pengiriman')
    .select('*')
    .eq('no_resi', no_resi)
    .order('tanggal', { ascending: false });

  res.json({
    success: true,
    data: { ...pengiriman, statusHistory: statusHistory || [] }
  });
});

// Public tracking search
app.get('/api/public/tracking', async (req, res) => {
  const { search } = req.query;
  if (!search) return res.status(400).json({ message: 'Parameter search harus diisi' });

  const { data, error } = await supabase
    .from('pengiriman')
    .select('*')
    .or(`no_resi.ilike.%${search}%,nama_pengirim.ilike.%${search}%,nama_penerima.ilike.%${search}%`)
    .order('tanggal', { ascending: false })
    .limit(10);

  if (error || !data || data.length === 0)
    return res.status(404).json({ message: 'Nomor resi tidak ditemukan', data: [] });

  res.json({ success: true, data });
});

// Public tracking route (shorthand)
app.get('/api/tracking/:no_resi', async (req, res) => {
  const { no_resi } = req.params;

  const { data: pengiriman, error } = await supabase
    .from('pengiriman')
    .select('*')
    .eq('no_resi', no_resi)
    .single();

  if (error || !pengiriman)
    return res.status(404).json({ message: 'Nomor resi tidak ditemukan' });

  const { data: history } = await supabase
    .from('status_pengiriman')
    .select('*')
    .eq('no_resi', no_resi)
    .order('tanggal', { ascending: false });

  res.json({ data: { ...pengiriman, statusHistory: history || [] } });
});

// ==================== GLOBAL ERROR HANDLERS ====================
process.on('uncaughtException', (err) => console.error('Uncaught Exception:', err));
process.on('unhandledRejection', (reason) => console.error('Unhandled Rejection:', reason));

// ==================== START SERVER ====================
server.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`✅ WebSocket server running on ws://localhost:${PORT}`);
});