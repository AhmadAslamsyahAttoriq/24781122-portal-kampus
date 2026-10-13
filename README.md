# Portal Kampus (Latihan Keamanan Web)

> **PROYEK LATIHAN.** Seluruh akun dan data di aplikasi ini **sintetis**, dibuat untuk
> latihan mata kuliah Keamanan Sistem Informasi. Aplikasi ini **sengaja dibuat rentan**
> untuk tujuan edukasi. Jangan gunakan pola kodenya di aplikasi nyata, dan jangan
> menguji aplikasi ini dengan data pribadi asli.

- **NPM:** 24781122
- **Dibuat dengan:** Node.js murni (modul bawaan saja: `http`, `fs`, `crypto`), tanpa
  framework atau database eksternal. Data disimpan di berkas `data/db.json`.

## Peran dan fitur
- **Mahasiswa** — masuk, melihat nilai sendiri, mengunggah tugas (teks), ikut diskusi.
- **Dosen** — melihat dan menginput nilai seluruh mahasiswa, melihat tugas yang masuk, ikut diskusi.
- **Admin** — mengelola akun (tambah/hapus), plus semua hak dosen.

## Akun contoh (sintetis — ganti sebelum dipakai di luar latihan)
| Username | Sandi | Peran |
|---|---|---|
| `dina` | `dina123` | mahasiswa |
| `rafi` | `rafi123` | mahasiswa |
| `budi` | `budi123` | dosen |
| `admin` | `admin123` | admin |

## Kerentanan yang disengaja

### 1. IDOR / kontrol akses lemah — `GET /grades?student_id=...`
Saat mahasiswa membuka `/grades`, sistem mengambil `student_id` dari **parameter URL**
dan langsung menampilkan nilai untuk ID tersebut — **tanpa memeriksa** apakah ID itu
milik mahasiswa yang sedang login.

**Cara membuktikan:** login sebagai `dina` (ID `S001`), lalu buka
`/grades?student_id=S002`. Nilai milik Rafi (S002) ikut tampil, padahal Dina tidak
berwenang melihatnya.

**Kode yang relevan** (`server.js`, fungsi `handleGrades`):
```js
// KERENTANAN SENGAJA (IDOR): jika parameter student_id diisi, data langsung
// ditampilkan tanpa memeriksa apakah itu benar milik pengguna yang login.
const targetId = query.student_id || user.id;
const rows = db.grades.filter((g) => g.studentId === targetId);
```

**Kontrol yang seharusnya ada:** sebelum mengambil data, periksa apakah
`targetId === user.id`, atau tolak permintaan jika bukan milik sendiri dan peran
bukan dosen/admin.

### 2. Eskalasi hak akses — `POST /profile`
Halaman profil menampilkan kolom "Peran" sebagai `<select>` yang **tidak dikunci**,
dan server menyimpan apa pun yang dikirim pada field `role` tanpa memeriksa apakah
pengirimnya berwenang mengubah peran (seharusnya hanya admin).

**Cara membuktikan:** login sebagai `dina` (mahasiswa), buka `/profile`, ubah
dropdown "Peran" menjadi `admin`, simpan. Setelah itu `/admin/users` yang tadinya
terlarang menjadi bisa dibuka.

**Kode yang relevan** (`server.js`, fungsi `handleProfilePost`):
```js
// KERENTANAN SENGAJA (eskalasi hak akses): server menyimpan field "role" apa
// adanya dari permintaan klien, tanpa memeriksa apakah pengirim berwenang.
user.nama = body.nama || user.nama;
if (body.role) user.role = body.role;
```

**Kontrol yang seharusnya ada:** field `role` tidak boleh diterima dari pengguna
biasa sama sekali; perubahan peran hanya lewat endpoint `/admin/users/*` yang sudah
memeriksa `user.role === "admin"`.

## Yang sengaja TIDAK dijadikan kerentanan (praktik baik tetap dijaga)
- Sandi disimpan ter-hash (`scrypt`), bukan teks biasa.
- Input pengguna di-escape sebelum dirender ke HTML (mencegah stored XSS).
- Query database tidak dibentuk dengan menyambung string SQL (tidak memakai SQL
  sama sekali — data disimpan di berkas JSON), sehingga SQL injection tidak relevan
  di aplikasi ini.

## Cara menjalankan secara lokal
```
npm install    # tidak ada dependency eksternal, tapi aman dijalankan
npm start
```
Buka `http://localhost:3000`.

## Cara deploy (Render.com, gratis)
1. Push folder ini ke repo GitHub publik.
2. Buka [render.com](https://render.com), daftar/masuk dengan akun GitHub.
3. **New → Web Service**, pilih repo ini.
4. **Build Command:** `npm install` — **Start Command:** `npm start`.
5. Klik **Create Web Service**. Tunggu proses build selesai, lalu buka URL yang diberikan.

**Catatan:** penyimpanan data (`data/db.json`) tidak permanen di hosting gratis
(reset saat layanan redeploy/sleep). Ini cukup untuk keperluan latihan dan audit,
karena seluruh data memang sintetis dan dibuat ulang otomatis saat pertama kali
dijalankan.

## Audit keamanan
Dua kerentanan di atas (IDOR dan eskalasi hak akses) adalah **satu-satunya**
kerentanan yang disengaja pada aplikasi ini. Fitur lain (login, hashing sandi,
escaping output, otorisasi per-role pada endpoint admin dan dosen) dibuat mengikuti
praktik yang wajar.
