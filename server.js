// Portal Kampus (SINTETIS) — proyek latihan keamanan web.
// Kerentanan yang DISENGAJA untuk tujuan edukasi:
//   1) IDOR / kontrol akses lemah — GET /grades?student_id=... tidak memeriksa
//      apakah mahasiswa yang login adalah pemilik data nilai tersebut.
//   2) Eskalasi hak akses — POST /profile menerima field "role" dari klien
//      dan menyimpannya apa adanya, tanpa memeriksa apakah yang mengirim
//      berwenang mengubah peran (seharusnya hanya admin).
// Jangan jadikan pola ini contoh pada aplikasi nyata.

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const querystring = require("querystring");

const DB_PATH = path.join(__dirname, "data", "db.json");
const PORT = process.env.PORT || 3000;

// ---------- util ----------
function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return salt + ":" + hash;
}
function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(":");
  const check = crypto.scryptSync(password, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(check));
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}
function newId(prefix) { return prefix + crypto.randomBytes(4).toString("hex"); }

// ---------- data store (file JSON — cukup untuk latihan, bukan untuk produksi) ----------
function seedDb() {
  const users = [
    { id: "S001", nama: "Dina Pratiwi", username: "dina", role: "mahasiswa", password: hashPassword("dina123") },
    { id: "S002", nama: "Rafi Hidayat", username: "rafi", role: "mahasiswa", password: hashPassword("rafi123") },
    { id: "D001", nama: "Budi Santoso, S.Kom., M.T.", username: "budi", role: "dosen", password: hashPassword("budi123") },
    { id: "A001", nama: "Admin Portal", username: "admin", role: "admin", password: hashPassword("admin123") }
  ];
  const grades = [
    { studentId: "S001", mataKuliah: "Keamanan Sistem Informasi", nilai: "A" },
    { studentId: "S001", mataKuliah: "Basis Data", nilai: "B+" },
    { studentId: "S002", mataKuliah: "Keamanan Sistem Informasi", nilai: "B" },
    { studentId: "S002", mataKuliah: "Basis Data", nilai: "A-" }
  ];
  const assignments = [];
  const discussion = [
    { id: newId("d"), userId: "D001", nama: "Budi Santoso, S.Kom., M.T.", pesan: "Selamat datang di forum diskusi kelas.", waktu: new Date().toISOString() }
  ];
  return { users, grades, assignments, discussion };
}
function loadDb() {
  if (!fs.existsSync(DB_PATH)) fs.writeFileSync(DB_PATH, JSON.stringify(seedDb(), null, 2));
  return JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
}
function saveDb(db) { fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2)); }

// ---------- sessions (in-memory; cukup untuk latihan) ----------
const sessions = new Map(); // token -> userId
function parseCookies(req) {
  const h = req.headers.cookie || "";
  const out = {};
  h.split(";").forEach((p) => {
    const i = p.indexOf("=");
    if (i > -1) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function getUser(req, db) {
  const token = parseCookies(req).sid;
  if (!token || !sessions.has(token)) return null;
  return db.users.find((u) => u.id === sessions.get(token)) || null;
}

// ---------- body parsing (urlencoded form) ----------
function readBody(req) {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => resolve(querystring.parse(data)));
  });
}

// ---------- layout ----------
function layout(user, title, body) {
  const nav = user
    ? `<nav>
        <a href="/dashboard">Dashboard</a>
        <a href="/grades">Nilai</a>
        <a href="/assignments">Tugas</a>
        <a href="/discussion">Diskusi</a>
        ${user.role === "admin" ? '<a href="/admin/users">Kelola Akun</a>' : ""}
        <a href="/profile">Profil (${escapeHtml(user.nama)} · ${escapeHtml(user.role)})</a>
        <a href="/logout">Keluar</a>
      </nav>`
    : "";
  return `<!doctype html><html lang="id"><head><meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} · Portal Kampus (Latihan)</title>
  <link rel="stylesheet" href="/style.css"></head>
  <body>
  <header><strong>Portal Kampus — LATIHAN KEAMANAN</strong>
  <p class="warn">Seluruh akun dan data di situs ini SINTETIS, dibuat untuk latihan keamanan web. Jangan masukkan data asli.</p></header>
  ${nav}
  <main><h1>${escapeHtml(title)}</h1>${body}</main>
  </body></html>`;
}
function redirect(res, loc) { res.writeHead(302, { Location: loc }); res.end(); }

// ---------- route handlers ----------
async function handleLoginGet(req, res, db, user) {
  if (user) return redirect(res, "/dashboard");
  res.end(layout(null, "Masuk", `
    <form method="post" action="/login">
      <label>Username <input name="username" required></label>
      <label>Sandi <input name="password" type="password" required></label>
      <button type="submit">Masuk</button>
    </form>
    <p class="hint">Akun contoh (sintetis): dina/dina123 (mahasiswa), rafi/rafi123 (mahasiswa), budi/budi123 (dosen), admin/admin123 (admin).</p>
  `));
}
async function handleLoginPost(req, res, db) {
  const body = await readBody(req);
  const u = db.users.find((x) => x.username === body.username);
  if (!u || !verifyPassword(body.password || "", u.password)) {
    return res.end(layout(null, "Masuk", `<p class="error">Username atau sandi salah.</p><p><a href="/login">Coba lagi</a></p>`));
  }
  const token = crypto.randomBytes(24).toString("hex");
  sessions.set(token, u.id);
  res.writeHead(302, { Location: "/dashboard", "Set-Cookie": `sid=${token}; HttpOnly; Path=/; SameSite=Lax` });
  res.end();
}
function handleLogout(req, res) {
  const token = parseCookies(req).sid;
  if (token) sessions.delete(token);
  res.writeHead(302, { Location: "/login", "Set-Cookie": "sid=; Path=/; Max-Age=0" });
  res.end();
}
function handleDashboard(req, res, db, user) {
  res.end(layout(user, "Dashboard", `
    <p>Selamat datang, ${escapeHtml(user.nama)}. Peran Anda: <strong>${escapeHtml(user.role)}</strong>.</p>
    <ul>
      <li><a href="/grades">Lihat nilai</a></li>
      <li><a href="/assignments">Tugas</a></li>
      <li><a href="/discussion">Forum diskusi</a></li>
      ${user.role === "admin" ? '<li><a href="/admin/users">Kelola akun</a></li>' : ""}
    </ul>
  `));
}

// --- Nilai (berisi kerentanan IDOR) ---
function handleGrades(req, res, db, user, query) {
  if (user.role === "mahasiswa") {
    // KERENTANAN SENGAJA (IDOR): jika parameter student_id diisi, data langsung
    // ditampilkan tanpa memeriksa apakah itu benar milik pengguna yang login.
    const targetId = query.student_id || user.id;
    const rows = db.grades.filter((g) => g.studentId === targetId);
    const target = db.users.find((u) => u.id === targetId);
    return res.end(layout(user, "Nilai", `
      <p>Menampilkan nilai untuk: <strong>${escapeHtml(targetId)}</strong>${target ? " — " + escapeHtml(target.nama) : ""}</p>
      ${rows.length === 0 ? "<p>Tidak ada data.</p>" : `<table><tr><th>Mata kuliah</th><th>Nilai</th></tr>
      ${rows.map((r) => `<tr><td>${escapeHtml(r.mataKuliah)}</td><td>${escapeHtml(r.nilai)}</td></tr>`).join("")}</table>`}
      <p class="hint">Coba ubah angka di akhir alamat menjadi <code>/grades?student_id=S002</code> atau sebaliknya untuk menguji kontrol akses.</p>
    `));
  }
  // dosen & admin: lihat semua + form input nilai
  const rows = db.grades;
  const students = db.users.filter((u) => u.role === "mahasiswa");
  res.end(layout(user, "Nilai (Dosen/Admin)", `
    <table><tr><th>NIM</th><th>Nama</th><th>Mata kuliah</th><th>Nilai</th></tr>
    ${rows.map((r) => {
      const s = db.users.find((u) => u.id === r.studentId);
      return `<tr><td>${escapeHtml(r.studentId)}</td><td>${escapeHtml(s ? s.nama : "-")}</td><td>${escapeHtml(r.mataKuliah)}</td><td>${escapeHtml(r.nilai)}</td></tr>`;
    }).join("")}</table>
    <h2>Input nilai</h2>
    <form method="post" action="/grades/update">
      <label>Mahasiswa
        <select name="studentId">${students.map((s) => `<option value="${s.id}">${escapeHtml(s.nama)} (${s.id})</option>`).join("")}</select>
      </label>
      <label>Mata kuliah <input name="mataKuliah" required></label>
      <label>Nilai <input name="nilai" required></label>
      <button type="submit">Simpan</button>
    </form>
  `));
}
async function handleGradesUpdate(req, res, db, user) {
  if (user.role !== "dosen" && user.role !== "admin") { res.writeHead(403); return res.end("Dilarang."); }
  const body = await readBody(req);
  const existing = db.grades.find((g) => g.studentId === body.studentId && g.mataKuliah === body.mataKuliah);
  if (existing) existing.nilai = body.nilai;
  else db.grades.push({ studentId: body.studentId, mataKuliah: body.mataKuliah, nilai: body.nilai });
  saveDb(db);
  redirect(res, "/grades");
}

// --- Tugas ---
function handleAssignments(req, res, db, user) {
  if (user.role === "mahasiswa") {
    const mine = db.assignments.filter((a) => a.studentId === user.id);
    return res.end(layout(user, "Tugas", `
      <form method="post" action="/assignments/upload">
        <label>Judul tugas <input name="judul" required></label>
        <label>Isi tugas (teks, disimpan sebagai file .txt) <textarea name="isi" rows="6" required></textarea></label>
        <button type="submit">Unggah</button>
      </form>
      <h2>Tugas saya</h2>
      ${mine.length === 0 ? "<p>Belum ada tugas diunggah.</p>" : `<ul>${mine.map((a) => `<li>${escapeHtml(a.judul)} — ${new Date(a.waktu).toLocaleString("id-ID")}</li>`).join("")}</ul>`}
    `));
  }
  const all = db.assignments;
  res.end(layout(user, "Tugas Mahasiswa", `
    ${all.length === 0 ? "<p>Belum ada tugas yang diunggah mahasiswa.</p>" : `<ul>${all.map((a) => {
      const s = db.users.find((u) => u.id === a.studentId);
      return `<li><strong>${escapeHtml(a.judul)}</strong> oleh ${escapeHtml(s ? s.nama : a.studentId)} — ${new Date(a.waktu).toLocaleString("id-ID")}<br><pre>${escapeHtml(a.isi)}</pre></li>`;
    }).join("")}</ul>`}
  `));
}
async function handleAssignmentUpload(req, res, db, user) {
  if (user.role !== "mahasiswa") { res.writeHead(403); return res.end("Dilarang."); }
  const body = await readBody(req);
  db.assignments.push({ id: newId("tgs"), studentId: user.id, judul: body.judul || "(tanpa judul)", isi: body.isi || "", waktu: new Date().toISOString() });
  saveDb(db);
  redirect(res, "/assignments");
}

// --- Diskusi ---
function handleDiscussion(req, res, db, user) {
  res.end(layout(user, "Forum Diskusi", `
    <form method="post" action="/discussion/post">
      <label>Pesan <textarea name="pesan" rows="3" required></textarea></label>
      <button type="submit">Kirim</button>
    </form>
    <ul class="forum">
    ${db.discussion.slice().reverse().map((d) => `<li><strong>${escapeHtml(d.nama)}</strong> <span class="time">${new Date(d.waktu).toLocaleString("id-ID")}</span><br>${escapeHtml(d.pesan)}</li>`).join("")}
    </ul>
  `));
}
async function handleDiscussionPost(req, res, db, user) {
  const body = await readBody(req);
  db.discussion.push({ id: newId("d"), userId: user.id, nama: user.nama, pesan: body.pesan || "", waktu: new Date().toISOString() });
  saveDb(db);
  redirect(res, "/discussion");
}

// --- Profil (berisi kerentanan eskalasi hak akses) ---
function handleProfile(req, res, db, user) {
  res.end(layout(user, "Profil Saya", `
    <form method="post" action="/profile">
      <label>Nama <input name="nama" value="${escapeHtml(user.nama)}" required></label>
      <label>Peran
        <select name="role">
          <option value="mahasiswa" ${user.role === "mahasiswa" ? "selected" : ""}>mahasiswa</option>
          <option value="dosen" ${user.role === "dosen" ? "selected" : ""}>dosen</option>
          <option value="admin" ${user.role === "admin" ? "selected" : ""}>admin</option>
        </select>
      </label>
      <button type="submit">Simpan</button>
    </form>
    <p class="hint">Perhatikan: kolom "Peran" di atas seharusnya tidak bisa diubah sembarang pengguna. Ini kerentanan yang disengaja untuk latihan.</p>
  `));
}
async function handleProfilePost(req, res, db, user) {
  const body = await readBody(req);
  // KERENTANAN SENGAJA (eskalasi hak akses): server menyimpan field "role" apa
  // adanya dari permintaan klien, tanpa memeriksa apakah pengirim berwenang
  // (seharusnya hanya admin yang boleh mengubah peran pengguna lain/diri sendiri).
  user.nama = body.nama || user.nama;
  if (body.role) user.role = body.role;
  saveDb(db);
  redirect(res, "/profile");
}

// --- Admin: kelola akun ---
function handleAdminUsers(req, res, db, user) {
  if (user.role !== "admin") { res.writeHead(403); return res.end(layout(user, "Dilarang", "<p>Halaman ini khusus admin.</p>")); }
  res.end(layout(user, "Kelola Akun", `
    <table><tr><th>ID</th><th>Nama</th><th>Username</th><th>Peran</th><th></th></tr>
    ${db.users.map((u) => `<tr><td>${escapeHtml(u.id)}</td><td>${escapeHtml(u.nama)}</td><td>${escapeHtml(u.username)}</td><td>${escapeHtml(u.role)}</td>
      <td>${u.id !== user.id ? `<form method="post" action="/admin/users/delete" style="display:inline"><input type="hidden" name="id" value="${u.id}"><button type="submit">Hapus</button></form>` : ""}</td></tr>`).join("")}
    </table>
    <h2>Tambah akun</h2>
    <form method="post" action="/admin/users/create">
      <label>Nama <input name="nama" required></label>
      <label>Username <input name="username" required></label>
      <label>Sandi awal <input name="password" required></label>
      <label>Peran
        <select name="role"><option value="mahasiswa">mahasiswa</option><option value="dosen">dosen</option><option value="admin">admin</option></select>
      </label>
      <button type="submit">Buat akun</button>
    </form>
  `));
}
async function handleAdminUserCreate(req, res, db, user) {
  if (user.role !== "admin") { res.writeHead(403); return res.end("Dilarang."); }
  const body = await readBody(req);
  const id = newId(body.role === "dosen" ? "D" : body.role === "admin" ? "A" : "S");
  db.users.push({ id, nama: body.nama, username: body.username, role: body.role, password: hashPassword(body.password) });
  saveDb(db);
  redirect(res, "/admin/users");
}
async function handleAdminUserDelete(req, res, db, user) {
  if (user.role !== "admin") { res.writeHead(403); return res.end("Dilarang."); }
  const body = await readBody(req);
  db.users = db.users.filter((u) => u.id !== body.id);
  saveDb(db);
  redirect(res, "/admin/users");
}

// ---------- server ----------
const PUBLIC_DIR = path.join(__dirname, "public");
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  const pathname = url.pathname;
  const query = Object.fromEntries(url.searchParams);

  if (pathname === "/style.css") {
    const css = fs.readFileSync(path.join(PUBLIC_DIR, "style.css"));
    res.writeHead(200, { "Content-Type": "text/css" });
    return res.end(css);
  }

  const db = loadDb();
  const user = getUser(req, db);
  const needsAuth = !["/login", "/style.css"].includes(pathname);
  if (needsAuth && !user) return redirect(res, "/login");

  try {
    if (pathname === "/" ) return redirect(res, user ? "/dashboard" : "/login");
    if (pathname === "/login" && req.method === "GET") return await handleLoginGet(req, res, db, user);
    if (pathname === "/login" && req.method === "POST") return await handleLoginPost(req, res, db);
    if (pathname === "/logout") return handleLogout(req, res);
    if (pathname === "/dashboard") return handleDashboard(req, res, db, user);
    if (pathname === "/grades" && req.method === "GET") return handleGrades(req, res, db, user, query);
    if (pathname === "/grades/update" && req.method === "POST") return await handleGradesUpdate(req, res, db, user);
    if (pathname === "/assignments" && req.method === "GET") return handleAssignments(req, res, db, user);
    if (pathname === "/assignments/upload" && req.method === "POST") return await handleAssignmentUpload(req, res, db, user);
    if (pathname === "/discussion" && req.method === "GET") return handleDiscussion(req, res, db, user);
    if (pathname === "/discussion/post" && req.method === "POST") return await handleDiscussionPost(req, res, db, user);
    if (pathname === "/profile" && req.method === "GET") return handleProfile(req, res, db, user);
    if (pathname === "/profile" && req.method === "POST") return await handleProfilePost(req, res, db, user);
    if (pathname === "/admin/users" && req.method === "GET") return handleAdminUsers(req, res, db, user);
    if (pathname === "/admin/users/create" && req.method === "POST") return await handleAdminUserCreate(req, res, db, user);
    if (pathname === "/admin/users/delete" && req.method === "POST") return await handleAdminUserDelete(req, res, db, user);

    res.writeHead(404); res.end("Halaman tidak ditemukan.");
  } catch (e) {
    res.writeHead(500); res.end("Terjadi kesalahan: " + e.message);
  }
});

server.listen(PORT, () => console.log("Portal kampus (latihan) jalan di port " + PORT));
