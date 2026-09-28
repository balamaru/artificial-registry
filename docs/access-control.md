# Administrasi pengguna dan hak akses

## Akun pertama dan upgrade

Pada database baru, aplikasi membuat akun lokal **admin** dengan role **super-admin**, email kosong, dan password acak 128-bit. Password dicetak sekali sesudah transaksi bootstrap berhasil, melalui log `BOOTSTRAP ADMIN username=admin temporary_password=...`. Jalankan `docker compose logs registry` untuk melihatnya. Startup beberapa replica tetap menghasilkan satu akun dan satu pesan password.

Login pertama membuka formulir wajib ganti password (12–72 byte); email opsional. Backend menolak semua endpoint registry dan pembuatan token sampai password diganti, termasuk bila UI dilewati. Hanya profil, ganti password, dan logout tersedia. Password baru harus berbeda; perubahan mencabut sesi awal dan user login ulang. Password log tidak disimpan dalam plaintext di database dan tidak dicetak ulang ketika restart. Jaga akses log instalasi.

Pada upgrade, akun lokal tertua dipromosikan menjadi super-admin; apabila tidak ada akun lokal, admin namespace existing dengan namespace tertua digunakan; role reader/publisher tidak dipromosikan melalui fallback ini. Membership `reader`, `publisher`, dan `admin` existing disalin sekali ke model grant baru. Migrasi tidak mengembalikan grant yang sudah dicabut ketika aplikasi restart. Session dan paket existing dipertahankan. Backup database sebelum upgrade, lalu jalankan `docker compose up -d --build`; tidak perlu menghapus volume PostgreSQL.

Aturan bootstrap admin lokal berlaku juga untuk **OIDC/hybrid**. User lain tetap mengikuti provider OIDC yang dikonfigurasi: login pertama membuat identitas registry dengan role **user**, tanpa grant namespace. Tidak ada promosi super-admin dari login OIDC pertama. Administrator memberi role/grant setelah user muncul. Mode `oidc` menyediakan login lokal hanya bagi akun lokal super-admin; user biasa login melalui provider. Password user OIDC tetap dikelola provider.

## Pengelolaan pengguna

Login sebagai super-admin, pilih **Users & access**:

1. **Add user**: masukkan email, username, password awal, serta role registry (`user`, `user-delete`, atau `super-admin`). Session admin tetap aktif.
2. Klik **Manage** pada user untuk mengatur role registry, status active/disabled, atau reset password lokal.
3. Tambahkan grant dengan scope namespace tertentu atau **All namespaces**, lalu pilih satu atau beberapa role. Ctrl/Cmd + klik untuk memilih beberapa role.
4. Gunakan **Remove grant** untuk mencabut seluruh role pada scope tersebut.

Super-admin selalu memiliki seluruh akses namespace dan administrasi pengguna. User biasa memperoleh akses hanya melalui grant. Menonaktifkan akun atau reset password mencabut seluruh session dan token CLI user tersebut. Status disabled juga diperiksa ketika menggunakan bearer token OIDC. Super-admin tidak dapat menonaktifkan atau menurunkan role dirinya sendiri; ini mencegah kehilangan admin terakhir. Password tidak dikembalikan melalui API dan tidak ditulis ke audit.

Registrasi mandiri lokal ditutup permanen: UI hanya menampilkan login, dan `POST /auth/register` selalu mengembalikan 403. Variabel lama `REGISTRATION_ENABLED` diabaikan, termasuk jika bernilai true. User lokal baru meminta akun kepada administrator; administrator membuatnya melalui **Add user**, lalu menetapkan role namespace atau scope `*`. Pada mode `oidc`, user biasa tetap berasal dari provider sehingga formulir Add user lokal disembunyikan. Akun, password, session, dan grant existing dipertahankan pada upgrade; tidak ada pembuatan ulang admin atau reset password otomatis untuk database yang telah digunakan.

## Matriks role namespace

Izin bersifat gabungan: semua grant untuk namespace terkait dan scope `*` dijumlahkan. Tidak ada deny override. Grant `*` juga berlaku pada namespace yang dibuat kemudian. Mencabut grant namespace tidak membatalkan akses yang masih diberikan oleh grant `*`.

| Role | Metadata/list | Download | Upload baru | Update ZIP | Delete | Review/rescan | Audit/analytics | Kelola anggota |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| read-only | Ya | Ya | — | — | — | — | — | — |
| write-only | — | — | Ya | — | — | — | — | — |
| read-write | Ya | Ya | Ya | Ya | — | — | — | — |
| update | Ya | — | — | Ya | — | — | — | — |
| delete | Ya | — | — | — | Ya | — | — | — |
| reviewer | Ya | Ya | — | — | — | Ya | — | — |
| auditor | Ya | — | — | — | — | — | Ya | — |
| maintainer | Ya | Ya | Ya | Ya | Ya | Ya | Ya | — |
| admin | Ya | Ya | Ya | Ya | Ya | Ya | Ya | Ya |

`read-write`, `maintainer`, dan `admin` juga boleh mengirim usage. `read-only` tidak memiliki operasi tulis, termasuk telemetry. Alias existing `reader` tetap memiliki metadata/download/usage-write, dan `publisher` memiliki metadata/download/upload/usage-write untuk kompatibilitas. Katalog lengkap tersedia di `GET /v1/roles`.

Metadata meliputi nama/versi, hash, status, revision, dan hasil scan; role update/delete tidak menerima isi ZIP. Write-only hanya melihat namespace yang boleh diakses dan formulir upload, tanpa daftar skill atau download. Menggabungkan read-only + write-only memberikan read/upload, tetapi tidak update; gunakan read-write bila update dibutuhkan.

Hanya super-admin dan user dengan role `admin` pada scope `*` yang dapat membuat namespace. Pembuat namespace memperoleh grant admin pada namespace tersebut. Admin namespace boleh menambahkan/mengubah/mencabut anggota dalam namespace-nya melalui username, email, atau subject ID existing, tetapi tidak dapat memberikan grant global atau mengelola akun registry. Mengubah role anggota mengganti seluruh role khusus namespace tersebut. User tidak boleh menurunkan/menghapus assignment admin dirinya sendiri melalui endpoint anggota.

## Pencarian user pada Members

Klik kolom **Search username, email, or subject ID** untuk menampilkan daftar akun aktif. Saat mengetik, daftar otomatis difilter berdasarkan potongan username, email, atau subject ID tanpa membedakan huruf besar/kecil. Pilih user dari daftar, lalu buka **Choose roles** dan centang satu atau beberapa role; tidak perlu Ctrl/Cmd. Kolom pencarian, dropdown role, dan tombol Set role memiliki tinggi yang sama. Tombol panah dan Enter dapat digunakan untuk memilih user, dan Escape menutup dropdown.

Daftar mencakup akun yang belum menjadi anggota namespace agar admin dapat menambahkannya. Akun disabled tidak ditampilkan. Daftar dimuat 50 akun per halaman; **Load more users** menampilkan hasil berikutnya. Role hanya disimpan setelah menekan **Set role**. Mengedit teks pencarian membatalkan pilihan user sebelumnya untuk mencegah assignment ke akun yang salah.

Endpoint `GET /v1/namespaces/{ns}/member-candidates?q=&limit=50&offset=0` memerlukan izin `members` pada namespace tersebut. Response berisi `items` (subject, username, email saja) dan `has_more`. Namespace admin dapat melakukan pencarian ini tanpa akses administrasi user global; password, role registry, dan grant namespace lain tidak disertakan.

## API administrasi

Endpoint berikut memerlukan super-admin, kecuali list/delete user juga menerima role registry `user-delete`; cookie request mutasi memerlukan `X-Registry-CSRF: 1` seperti endpoint lainnya.

| Endpoint | Fungsi |
| --- | --- |
| `GET /v1/admin/users?q=&limit=50&offset=0` | Cari/list user beserta grant, tanpa hash password |
| `DELETE /v1/admin/users/{subject}` | Hapus akun dan cabut akses; user-delete hanya boleh menghapus user biasa |
| `POST /v1/admin/users` | Buat akun lokal |
| `PATCH /v1/admin/users/{subject}` | Ubah `system_role`, `disabled`, atau `password` |
| `PUT /v1/admin/users/{subject}/grants` | Ganti seluruh grant user secara atomik; array kosong mencabut semuanya |
| `GET /v1/admin/audit` | Audit create/update user dan perubahan grant |

Contoh body pembuatan user dengan grant awal:

```json
{
  "email": "developer@example.com",
  "username": "developer",
  "password": "replace-with-secure-password",
  "system_role": "user",
  "grants": [
    {"namespace": "platform", "roles": ["read-write", "delete"]},
    {"namespace": "documentation", "roles": ["read-only"]}
  ]
}
```

Namespace harus sudah ada. Untuk akses read-only ke semua namespace, kirim ke endpoint grants:

```json
{"grants": [{"namespace": "*", "roles": ["read-only"]}]}
```

Endpoint membership menerima `{"roles":["read-only","update"]}` atau bentuk lama `{"role":"reader"}`. `GET /v1/namespaces` mengembalikan `roles` dan `permissions` efektif agar klien bisa menampilkan operasi yang diperbolehkan. Kontrol izin tetap diterapkan di server.

## Update dan delete skill

Di UI, **Update ZIP** membuka dialog replacement untuk satu versi. Endpoint API:

```text
PUT /v1/namespaces/{ns}/skills/{skill}/versions/{version}
Content-Type: application/zip
If-Match: <sha256 saat ini dari daftar skill>
```

ZIP baru melewati scanner yang sama dengan upload. Operasi sukses menaikkan revision, menyimpan hash baru dan updated_at, serta selalu mengubah status menjadi **quarantined**. Approval ulang diperlukan sebelum download. Header If-Match wajib (428 bila tidak ada); hash yang berubah menghasilkan 412 agar perubahan user lain tidak tertimpa. Scan gagal/ZIP invalid tidak mengubah paket existing. Paket sebelumnya tidak diarsipkan: gunakan versi baru jika membutuhkan histori ZIP yang immutable.

**Delete version** pada UI menghapus satu versi secara permanen setelah konfirmasi. API `DELETE /v1/namespaces/{ns}/skills/{skill}/versions/{version}` membutuhkan If-Match hash saat ini. API `DELETE /v1/namespaces/{ns}/skills/{skill}` menghapus semua versi yang ada dalam snapshot operasi; versi baru yang diupload secara bersamaan tidak ikut dihapus. Delete memerlukan izin terpisah, tidak termasuk dalam read-write.

Update/delete dan auditnya menggunakan transaksi yang sama. Audit menyimpan hash/revision atau daftar versi yang dihapus. Audit dan usage historis tetap tersimpan setelah paket dihapus; download akan menghasilkan 404. Tidak ada recycle bin atau restore paket.

## Pengujian

Test integrasi mencakup bootstrap startup serentak, upgrade membership dan restart tanpa mengembalikan grant yang dicabut, registrasi ditolak, kewajiban ganti password awal, email opsional, scope spesifik/global/future namespace, gabungan role, write-only/read-only, namespace admin vs super-admin, stale hash, karantina setelah update, delete, disable/reset password, dan admin session yang tetap aktif setelah menambah user.

Smoke test browser `scripts/ui-smoke.cjs` membutuhkan **database disposable baru** dengan password admin bootstrap tersedia melalui `BOOTSTRAP_PASSWORD`. Ia menguji UI menggunakan dua konteks browser terpisah untuk admin dan member, termasuk perubahan role, update, delete, serta session yang dicabut. Jalankan hanya pada database disposable.


## Hapus user dan ganti password sendiri

Role registry **user-delete** dapat membuka **Users & access**, melihat daftar user tanpa namespace grant, dan menghapus user biasa. Hanya **super-admin** yang boleh menghapus akun dengan role registry super-admin/user-delete. Role namespace **admin** atau **delete** tidak memberikan hak menghapus akun registry. Semua akun dilarang menghapus dirinya sendiri. Tombol **Delete user** meminta konfirmasi.

Penghapusan menghapus profil lokal/password, session, dan membership, serta mencabut semua token. Skill, usage, dan audit tetap tersimpan. Subject ID dipertahankan sebagai identitas disabled dengan waktu penghapusan agar login OIDC tidak membuat ulang akun yang dihapus. Akun tersebut tidak muncul dalam pencarian user dan tidak bisa diaktifkan kembali lewat PATCH. Menghapus akun registry tidak menghapus akun di identity provider.

Setiap user lokal dapat membuka **My account & tokens → Change password**. Masukkan password lama, password baru minimal 12 dan maksimal 72 byte, serta konfirmasinya. Setelah berhasil, seluruh session dan token dicabut dan user harus login ulang. User SSO mengganti password pada identity provider. Bearer token CLI tidak dapat mengganti password sendiri.

## Token CLI dan token turunan

Buka **My account & tokens → Create CLI token**:

1. Buat token pertama dengan **New root token**, nama, masa berlaku, serta grant eksplisit.
2. Untuk membuat token turunan, pilih token existing pada **Parent token**. Token harus milik akun yang sama dan masih aktif.
3. Pilih namespace dan role, lalu klik **Add namespace grant**. Ulangi untuk scope lain bila diperlukan. Role dibandingkan berdasarkan izin efektif; misalnya read-write boleh diturunkan menjadi read-only.
4. Bila memerlukan administrasi akun, pilih role registry secara eksplisit. **user-delete** hanya untuk penghapusan user biasa; **super-admin** memberikan administrasi penuh terhadap akun dan grant registry. Role super-admin dapat membuat/mempromosikan akun dan mengganti grant, sehingga jangan memilihnya untuk token yang perlu isolasi namespace. Izin operasi skill tetap membutuhkan grant namespace eksplisit.
5. Klik **Create token**, salin secret yang tampil satu kali, dan simpan dengan aman. Daftar token hanya menampilkan prefix dan metadata. Tombol **Revoke** mencabut token beserta semua turunannya.

Masa berlaku root 1–365 hari (default 30); masa berlaku child otomatis dibatasi oleh sisa masa berlaku parent. Maksimal kedalaman turunan 8 dan 20 token aktif per akun. Izin child harus merupakan subset izin parent **dan** hak akun saat ini. Scope spesifik tidak dapat diperluas menjadi wildcard. Token hanya berlaku selama semua ancestor aktif. Pengurangan grant akun langsung membatasi akses token; disable, reset/ganti password, atau delete user mencabut seluruh token. Database menyimpan SHA-256 secret, bukan secret asli. Audit menyertakan ID token untuk tindakan yang dilakukan lewat token.

| Endpoint | Fungsi |
| --- | --- |
| `POST /auth/password` | Ganti password lokal: current_password, new_password; login interaktif wajib |
| `GET /auth/token-options?parent_id=...` | Pilihan grant/role dari akun atau parent milik sendiri |
| `POST /auth/tokens` | Buat root via login interaktif, atau child via login/token parent |
| `GET /auth/tokens` | Login interaktif melihat 100 token terbaru; bearer hanya melihat dirinya dan turunannya |
| `DELETE /auth/tokens/{id}` | Cabut token dan turunannya; bearer tidak boleh mencabut ancestor/sibling |

Untuk request bearer ke `POST /auth/tokens`, token yang sedang digunakan otomatis menjadi parent; parent_id lain ditolak. Login interaktif boleh memilih parent_id sendiri atau mengosongkannya untuk root. Token yang hilang tidak bisa ditampilkan ulang; buat pengganti dan cabut token lama. Token bukan pengganti session browser atau token OIDC.

Contoh administrasi dari Ubuntu/PowerShell dengan curl menggunakan header bearer (gunakan URL HTTPS server Anda). Contoh shell berikut memakai Bash dan tidak menyimpan secret di source code:

```bash
export REGISTRY_URL=https://registry.example.com
read -rsp 'Parent token: ' REGISTRY_TOKEN
export REGISTRY_TOKEN
echo

# List namespace sesuai izin token.
curl --fail-with-body "$REGISTRY_URL/v1/namespaces" \
  -H "Authorization: Bearer $REGISTRY_TOKEN"

# Buat child read-only untuk namespace platform. Secret child ditampilkan sekali.
curl --fail-with-body "$REGISTRY_URL/auth/tokens" \
  -H "Authorization: Bearer $REGISTRY_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"cli-read","expires_in_days":7,"grants":[{"namespace":"platform","roles":["read-only"]}]}'

# Delete user memerlukan role registry user-delete atau super-admin.
curl --fail-with-body -X DELETE "$REGISTRY_URL/v1/admin/users/SUBJECT_ID" \
  -H "Authorization: Bearer $REGISTRY_TOKEN"

unset REGISTRY_TOKEN
```

Smoke test tambahan `scripts/account-smoke.cjs` memverifikasi pembuatan root/child melalui UI, pilihan role yang dibatasi, revoke berantai, UI operator user-delete, ganti password, dan layout mobile. Gunakan database disposable kosong.
