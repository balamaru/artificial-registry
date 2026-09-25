# Administrasi pengguna dan hak akses

## Akun pertama dan upgrade

Akun pertama pada database baru otomatis menjadi **super-admin registry**. Pembuatan akun pertama diserialisasi dalam transaksi PostgreSQL, sehingga dua registrasi bersamaan tidak menghasilkan dua super-admin bootstrap. Akun yang diregistrasikan berikutnya selalu menjadi user biasa, walaupun request mencoba menyertakan role atau grant.

Pada upgrade, akun lokal tertua dipromosikan menjadi super-admin; apabila tidak ada akun lokal, admin namespace existing dengan namespace tertua digunakan; role reader/publisher tidak dipromosikan melalui fallback ini. Membership `reader`, `publisher`, dan `admin` existing disalin sekali ke model grant baru. Migrasi tidak mengembalikan grant yang sudah dicabut ketika aplikasi restart. Session dan paket existing dipertahankan. Backup database sebelum upgrade, lalu jalankan `docker compose up -d --build`; tidak perlu menghapus volume PostgreSQL.

Untuk instalasi OIDC baru tanpa akun existing, identitas pertama yang berhasil diautentikasi menjadi super-admin. Batasi siapa yang dapat login ke client OIDC ketika melakukan bootstrap. Setelah bootstrap, super-admin dapat mempromosikan user lain. Namespace admin **tidak** otomatis menjadi super-admin registry.

## Pengelolaan pengguna

Login sebagai super-admin, pilih **Users & access**:

1. **Add user**: masukkan email, username, password awal, serta role registry (`user` atau `super-admin`). Session admin tetap aktif.
2. Klik **Manage** pada user untuk mengatur role registry, status active/disabled, atau reset password lokal.
3. Tambahkan grant dengan scope namespace tertentu atau **All namespaces**, lalu pilih satu atau beberapa role. Ctrl/Cmd + klik untuk memilih beberapa role.
4. Gunakan **Remove grant** untuk mencabut seluruh role pada scope tersebut.

Super-admin selalu memiliki seluruh akses namespace dan administrasi pengguna. User biasa memperoleh akses hanya melalui grant. Menonaktifkan akun atau reset password mencabut seluruh session user tersebut. Status disabled juga diperiksa ketika menggunakan bearer token OIDC. Super-admin tidak dapat menonaktifkan atau menurunkan role dirinya sendiri; ini mencegah kehilangan admin terakhir. Password tidak dikembalikan melalui API dan tidak ditulis ke audit.

Registrasi mandiri masih mengikuti `REGISTRATION_ENABLED`. Set `false` setelah bootstrap bila semua akun berikutnya harus dibuat admin; **Add user** tetap tersedia. Pada `AUTH_MODE=oidc`, akun/password dibuat di provider. User muncul dalam administrasi registry setelah login pertama, lalu grant dapat diberikan.

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

## API administrasi

Semua endpoint berikut memerlukan super-admin; cookie request mutasi memerlukan `X-Registry-CSRF: 1` seperti endpoint lainnya.

| Endpoint | Fungsi |
| --- | --- |
| `GET /v1/admin/users?q=&limit=50&offset=0` | Cari/list user beserta grant, tanpa hash password |
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

Test integrasi mencakup bootstrap serentak, upgrade membership dan restart tanpa mengembalikan grant yang dicabut, larangan eskalasi role lewat register, scope spesifik/global/future namespace, gabungan role, write-only/read-only, namespace admin vs super-admin, stale hash, karantina setelah update, delete, disable/reset password, dan admin session yang tetap aktif setelah menambah user.

Smoke test browser `scripts/ui-smoke.cjs` membutuhkan **database kosong** agar akun pertamanya menjadi super-admin. Ia menguji UI menggunakan dua konteks browser terpisah untuk admin dan member, termasuk perubahan role, update, delete, serta session yang dicabut. Jalankan hanya pada database disposable.
