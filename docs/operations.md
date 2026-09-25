# Operasional dan pengujian

Semua fitur implementasi ini tersedia tanpa license key. Core service 2 (runtime evaluation / dry-run sandbox) tidak diimplementasikan. Kode skill tidak pernah dieksekusi.

## Login lokal

`AUTH_MODE=local` adalah default. UI awal menampilkan registrasi dengan email, username, dan password. Username mengikuti `[a-z][a-z0-9-]{0,62}`, password 12–72 byte. Password disimpan menggunakan bcrypt cost 12; token sesi acak disimpan sebagai SHA-256 dalam database, berlaku 24 jam, dan dicabut saat logout. Cookie memakai HttpOnly dan SameSite=Lax; Secure aktif ketika `PUBLIC_URL` menggunakan HTTPS. Session tidak disimpan di localStorage.

Registrasi terbuka untuk pengujian awal. Setelah semua pengguna terdaftar, set `REGISTRATION_ENABLED=false` untuk menutup registrasi baru; login akun yang sudah ada tetap berjalan. Akun tidak memperoleh akses ke namespace pengguna lain secara otomatis. Pembuat namespace menjadi admin. Admin dapat menambahkan anggota memakai subject ID yang ditampilkan di header UI. Role reader bisa membaca/download dan mengirim usage, publisher juga bisa upload, admin juga bisa review serta mengelola anggota. Pengguna tidak dapat mencabut atau menurunkan role admin dirinya sendiri.

`PUBLIC_URL` harus sama persis dengan origin browser, tanpa trailing slash, misalnya `http://localhost:8080` atau `https://skills.example.com`. Mengakses via `127.0.0.1` membutuhkan nilai origin yang sesuai. Request mutasi yang memakai cookie harus menyertakan `X-Registry-CSRF: 1`; UI sudah melakukannya. Origin asing ditolak. Tidak ada CORS lintas origin. Endpoint login/register dibatasi bersama menjadi 20 percobaan per IP per 15 menit. Di belakang reverse proxy, alamat proxy yang digunakan; header X-Forwarded-For tidak dipercaya. Terapkan pembatasan per klien di ingress bila diperlukan.

## Keycloak atau provider OIDC lain

Gunakan client OIDC dengan authorization code flow, PKCE S256, scope `openid profile email`, dan callback **persis** `${PUBLIC_URL}/auth/oidc/callback`.

```dotenv
AUTH_MODE=hybrid
PUBLIC_URL=http://localhost:8080
OIDC_ISSUER=https://sso.example.com/realms/team
OIDC_CLIENT_ID=artificial-registry
OIDC_CLIENT_SECRET=secret-dari-provider
OIDC_AUDIENCE=artificial-registry
```

`hybrid` menampilkan login lokal dan SSO; `oidc` hanya SSO. Public client dapat mengosongkan secret. Issuer discovery dan token endpoint harus bisa diakses oleh container registry; authorization endpoint harus bisa diakses browser. Untuk Keycloak lokal, gunakan hostname issuer yang sama dari browser dan container. Aplikasi memeriksa signature, issuer, audience, expiry, state, dan nonce. Tidak ada penggabungan akun berdasarkan email; subject lokal dan subject provider merupakan identitas yang berbeda. Namespace lama dengan subject OIDC tetap memakai subject yang sama. Jangan mengganti issuer pada database yang sudah terisi tanpa migrasi membership.

Bearer token API tetap didukung pada mode OIDC/hybrid. Audience token API harus cocok dengan `OIDC_AUDIENCE` (default client ID). Konfigurasikan audience mapper di Keycloak jika diperlukan. Mode `dev` bersifat opsional dan membutuhkan `DEV_TOKEN` minimal 24 karakter; token itu tidak diterima pada mode local/hybrid/oidc.

Implementasi PKCE mengikuti [dokumentasi Go OAuth2](https://pkg.go.dev/golang.org/x/oauth2#S256ChallengeOption). Uji koneksi ke provider deployment sebelum digunakan tim; konfigurasi realm/provider tidak dibuat otomatis.

## Pemindaian

Setiap ZIP melalui pemeriksaan ukuran, path traversal, duplikasi, symlink, keberadaan SKILL.md, aturan prompt injection, pola script berisiko, dan Unicode kontrol tersembunyi. Hasil berisi skor 0–100, temuan, engine, dan cakupan. Approval hanya diizinkan pada versi quarantined dengan skor 100 dan nol temuan. Reject juga bisa mencabut versi published. Rescan mengembalikan versi ke quarantined sehingga selalu membutuhkan approval ulang.

`SCAN_OSV=true` mengaktifkan [OSV querybatch API](https://google.github.io/osv.dev/post-v1-querybatch/) gratis tanpa API key. Nama, ekosistem, dan versi dependency dikirim ke OSV; isi source tidak dikirim. Dukungan parser: `requirements.txt` dengan versi `==`, `go.mod`, dan `package-lock.json` v2/v3. Lock npm mencakup dependency transitif yang tercatat; requirements dan go.mod hanya mencakup daftar yang tercantum. Format lain yang dikenali tetapi belum didukung, versi tak terpin, gangguan jaringan, response parsial, dan advisori tambahan yang belum dibaca menjadi temuan yang memblokir approval. Batas 1.000 dependency per bundle, timeout OSV 20 detik. Perbaiki dependency lalu upload versi baru, atau rescan setelah gangguan jaringan selesai.

Untuk pengujian tanpa internet gunakan `SCAN_OSV=false`: hanya aturan statis yang dijalankan dan hasil scan menyatakan bahwa pemeriksaan advisori dinonaktifkan. Skor 100 berarti tidak ada temuan dari pemeriksaan yang berjalan, bukan sertifikasi keamanan. Scanner statis berbasis pola belum setara SAST dengan analisis aliran data, tidak mendeteksi semua prompt injection, dan tidak menegakkan scope akses script saat dijalankan di agen. CVE diperiksa terhadap database OSV pada waktu scan; tidak ada pemantauan advisori berkala otomatis.

## Data dan deployment

PostgreSQL menyimpan paket, metadata, pengguna, session, membership, audit, dan usage. Volume `pgdata` harus dibackup menggunakan `pg_dump`/backup PostgreSQL. Tidak ada kebutuhan layanan storage berbayar. Penyimpanan objek S3 belum diimplementasikan; PostgreSQL merupakan backend storage eksternal yang digunakan.

`/healthz` adalah liveness; `/readyz` memeriksa koneksi database. UI, API, dan file statis dibundel dalam satu executable Go tanpa CDN atau build JavaScript. Container berjalan non-root dengan filesystem read-only. Untuk Kubernetes, isi Secret `artificial-registry-config` dengan `DATABASE_URL`, `PUBLIC_URL`, `AUTH_MODE`, `REGISTRATION_ENABLED`, `SCAN_OSV`, dan konfigurasi OIDC bila digunakan. Gunakan ingress TLS dan origin publik yang sesuai.

Audit berisi upload, review, rescan, perubahan anggota, dan download; masih berada dalam database yang sama dan bukan log tahan manipulasi. Telemetry berasal dari klien, bukan monitoring agen otomatis. Savings USD dan token adalah estimasi klien, bukan ROI terverifikasi. API usage dapat dipanggil oleh reader; UI pencatatan/analytics tersedia untuk admin. Daftar skill memiliki pencarian, filter status, dan pagination; audit dan agregasi usage menampilkan maksimal 100 record/group.

## Verifikasi

```sh
go test ./...
go vet ./...
# PostgreSQL disposable; jangan gunakan database produksi.
TEST_DATABASE_URL='postgres://postgres:password@localhost:5432/registry_test?sslmode=disable' go test ./... -count=1
```

Integration test membuat akun dan namespace unik pada database disposable. Test mencakup registrasi/login/logout, password hash, RBAC, integritas download, karantina/approve/reject/rescan, usage, audit, dan perubahan anggota. Unit test memakai mock OSV sehingga tidak bergantung internet. Unit test UI memeriksa file statis dan header keamanan. Script `scripts/ui-smoke.cjs` menguji browser Chromium: registrasi, namespace, upload, approve, integritas download, analytics, audit, anggota, layout mobile, logout/login, dan error JavaScript.


Menjalankan smoke test browser (aplikasi dan database disposable sudah berjalan):

```sh
npm install --prefix /tmp/registry-browser playwright@1.58.2
/tmp/registry-browser/node_modules/.bin/playwright install --with-deps chromium
NODE_PATH=/tmp/registry-browser/node_modules BASE_URL=http://localhost:8080 \
  ZIP_FIXTURE=/path/to/safe-skill.zip node scripts/ui-smoke.cjs
```

`ZIP_FIXTURE` harus berisi SKILL.md aman di root. Opsional `SCREENSHOT_DIR` menunjuk direktori yang sudah ada untuk menyimpan screenshot desktop/mobile. Script membuat akun dan namespace baru pada setiap run. Aplikasi produksi tidak membutuhkan Node.js, npm, atau Chromium.


## Build gagal saat download modul Go

Builder menggunakan `GOPROXY=https://proxy.golang.org|direct`, Git dan CA certificates, serta maksimal tiga percobaan unduhan. Pemisah `|` mengizinkan fallback langsung ketika proxy mengalami error jaringan, sesuai [referensi Go modules](https://go.dev/ref/mod#environment-variables). Checksum `go.sum` dan `sum.golang.org` tetap diverifikasi. Modul go-jose yang digunakan adalah `github.com/go-jose/go-jose/v4`, bukan `github.com/go-jose/v4`.

```sh
docker compose --progress plain build registry
docker compose up -d
# Jika jaringan organisasi menyediakan proxy Go sendiri:
docker compose --progress plain build --build-arg GOPROXY=https://go-proxy.example.com registry
```

`exit code: 1` hanya ringkasan kegagalan; lihat pesan sebelum baris tersebut untuk penyebab sebenarnya (DNS, timeout/reset koneksi, sertifikat, atau checksum). Retry/fallback tidak memperbaiki jaringan yang memblokir semua jalur keluar. Jika hanya jaringan bridge builder di host Linux yang bermasalah, uji `docker build --network=host --progress=plain -t artificial-registry:local .`. Sesuaikan DNS/proxy/CA builder dengan jaringan deployment; jangan menonaktifkan TLS atau checksum untuk melewati error.
