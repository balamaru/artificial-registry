# Artificial Registry — versi uji awal (tanpa license key)

Registry privat AI skill dalam satu layanan Go dengan PostgreSQL.

## Menjalankan lokal

1. Salin `.env.example` menjadi `.env`, lalu ganti `POSTGRES_PASSWORD` dengan password acak (gunakan karakter URL-safe).
2. Jalankan `docker compose up --build`.
3. Buka **http://localhost:8080**. Registrasi dengan **email, username, dan password** (minimal 12 karakter), lalu buat namespace pertama.
4. Upload ZIP dengan `SKILL.md` di root. Tinjau hasil scan, approve versi yang bersih, lalu unduh dari UI.

Semua fitur yang tersedia gratis tanpa license key: core service **1** (scan statis/prompt, advisori dependency, trust score) dan **3** (telemetry, analytics, estimasi savings). Core service **2** (runtime sandbox) dikecualikan.

UI mencakup pencarian/filter/pagination skill, hasil scan, approve/reject/rescan, namespace, anggota/RBAC, analytics, audit, dan logout. Tidak membutuhkan Node.js atau CDN. Data disimpan di PostgreSQL.

Default `AUTH_MODE=local`. Gunakan `hybrid` untuk login lokal + SSO atau `oidc` untuk SSO saja. Isi `OIDC_ISSUER`, `OIDC_CLIENT_ID`, opsional `OIDC_CLIENT_SECRET` dan `OIDC_AUDIENCE`. Callback: `${PUBLIC_URL}/auth/oidc/callback`. Keycloak dan provider OIDC kompatibel lainnya didukung. Panduan konfigurasi, keamanan, dan pengujian: [docs/operations.md](docs/operations.md).

`SCAN_OSV=true` (default Compose) mengirim nama/versi dependency ke API OSV gratis untuk pemeriksaan advisori; source tidak dikirim. Untuk uji offline set `SCAN_OSV=false`. Mode offline hanya menjalankan aturan statis dan menampilkan batas cakupan tersebut pada hasil scan.

Contoh API lokal menggunakan session cookie:

```sh
curl -c cookies.txt -H 'Content-Type: application/json' \
  -d '{"email":"tester@example.com","username":"tester","password":"change-this-password"}' \
  http://localhost:8080/auth/register
curl -b cookies.txt -H 'X-Registry-CSRF: 1' -H 'Content-Type: application/json' \
  -d '{"name":"platform"}' http://localhost:8080/v1/namespaces
```

Untuk script lama, mode `dev` tetap mendukung `Authorization: Bearer $DEV_TOKEN`, jika token minimal 24 karakter dikonfigurasi. Mode ini hanya untuk pengujian lokal. Mode OIDC/hybrid mendukung bearer token provider dengan audience yang sesuai.

## API

| Method dan path | Akses | Fungsi |
| --- | --- | --- |
| `GET /v1/namespaces` | Pengguna login | Daftar namespace dan role |
| `POST /v1/namespaces` | Pengguna login | Buat namespace dan menjadi admin |
| `PUT /v1/namespaces/{ns}/members/{sub}` | Admin | Atur role `reader`, `publisher`, atau `admin` |
| `POST /v1/namespaces/{ns}/skills/{skill}/versions/{version}` | Publisher | Upload ZIP, scan, karantina |
| `POST /v1/namespaces/{ns}/skills/{skill}/versions/{version}/approve` | Admin | Publikasikan jika scan tanpa temuan |
| `GET /v1/namespaces/{ns}/skills` | Anggota | Daftar versi dan hasil scan |
| `GET /v1/namespaces/{ns}/skills/{skill}/versions/{version}` | Anggota | Unduh versi published |
| `POST /v1/namespaces/{ns}/skills/{skill}/versions/{version}/reject` | Admin | Tolak/cabut versi dengan alasan |
| `POST /v1/namespaces/{ns}/skills/{skill}/versions/{version}/rescan` | Admin | Scan ulang dan karantina kembali |
| `GET /v1/namespaces/{ns}/members` | Admin | Daftar anggota |
| `DELETE /v1/namespaces/{ns}/members/{sub}` | Admin | Cabut anggota selain diri sendiri |
| `GET /v1/namespaces/{ns}/audit` | Admin | 100 audit event terbaru |
| `POST /v1/namespaces/{ns}/usage` | Anggota | Kirim metrik pemanggilan skill |
| `GET /v1/namespaces/{ns}/usage` | Admin | Ringkasan penggunaan 30 hari |
| `GET /v1/mode`, `GET /healthz`, `GET /readyz` | Publik | Status mode dan health |

Contoh kirim usage setelah agen memakai skill yang sudah published:

```sh
curl -X POST -b cookies.txt -H 'X-Registry-CSRF: 1' -H 'Content-Type: application/json' \
  -d '{"skill":"example","version":"1.0.0","latency_ms":850,"success":true,"estimated_tokens_saved":120,"estimated_cost_usd":0.0024}' \
  http://localhost:8080/v1/namespaces/platform/usage
  
curl -b cookies.txt http://localhost:8080/v1/namespaces/platform/usage
```

Telemetry dicatat oleh klien. Success rate dan latency berasal dari event klien; token dan biaya adalah **estimasi yang dilaporkan klien**, bukan ROI terverifikasi. Aplikasi agen perlu memanggil API usage; pengunduhan paket bukan pemanggilan skill.

## Scanning dan batas keamanan

Paket ZIP dibatasi 10 MiB terkompresi, 8 MiB terurai, 2 MiB per file, dan 128 entri; traversal, symlink, dan nama duplikat ditolak. Hasil scan berisi skor, temuan, dan cakupan: pola prompt injection dalam Markdown/teks, pola kode berisiko dalam Python/Bash/JavaScript/Go, serta pola dependency tidak terpin atau sumber HTTP. Temuan apa pun menahan persetujuan; admin meninjau hasil sebelum publikasi.

Scanner menggunakan **analisis statis berbasis aturan** dan pemeriksaan advisori OSV opsional. Parser advisori mendukung requirements Python dengan versi ==, go.mod, dan package-lock.json v2/v3. Ia belum memiliki SAST penuh, analisis aliran data, deteksi prompt injection semantik, atau jaminan pembatasan network/file system saat script kelak dijalankan. Tidak ada script skill yang dieksekusi oleh registry. Jangan memakai skor sebagai sertifikasi keamanan. Format dependency yang belum didukung dan kegagalan OSV menjadi temuan yang memblokir approval saat OSV diaktifkan.

Berkas ZIP dan metadata tersimpan dalam PostgreSQL (`bytea`). Untuk beban besar, pindahkan blob ke penyimpanan S3 kompatibel dan terapkan backup serta retensi. Audit log masih berada dalam database yang sama dan belum tahan manipulasi. Login/register memiliki rate limit; daftar skill memiliki pagination (`limit`, `offset`), pencarian (`q`), dan filter (`status`). Migrasi schema berjalan idempotent saat startup; rollback schema otomatis belum tersedia.

## Deployment

`deploy/k8s/registry.yaml` adalah contoh Deployment dan Service. Ganti image dan buat Secret `artificial-registry-config` yang berisi `DATABASE_URL`, `PUBLIC_URL`, `AUTH_MODE`, serta konfigurasi autentikasi yang dijelaskan di docs/operations.md. Sediakan PostgreSQL secara terpisah serta ingress TLS. Image tidak membutuhkan environment variable lisensi.

Jalankan `go test ./...` memakai Go 1.26 dan `docker compose up --build` untuk uji integrasi. Core service 2 belum termasuk versi ini.
