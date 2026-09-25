# Artificial Registry — versi uji awal (tanpa lisensi)

Registry privat AI skill dalam satu layanan Go dengan PostgreSQL.

## Menjalankan lokal

1. Salin `.env.example` menjadi `.env`. Ganti `POSTGRES_PASSWORD` dan `DEV_TOKEN` dengan nilai acak yang panjang.
2. Jalankan `docker compose up --build`. API hanya terbuka di `http://127.0.0.1:8080`.
3. Set `TOKEN` sesuai `DEV_TOKEN`, lalu buat ZIP dengan `SKILL.md` di root.

```sh
export TOKEN='nilai-DEV_TOKEN-dari-.env'
curl -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"platform"}' http://127.0.0.1:8080/v1/namespaces

curl -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/zip' \
  --data-binary @skill.zip \
  http://127.0.0.1:8080/v1/namespaces/platform/skills/example/versions/1.0.0

curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8080/v1/namespaces/platform/skills/example/versions/1.0.0/approve

curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8080/v1/namespaces/platform/skills/example/versions/1.0.0 \
  --output downloaded.zip
```

Mode `dev` memakai satu identitas `dev-user` sehingga cocok hanya untuk uji lokal. Pada deployment sesungguhnya, set `AUTH_MODE=oidc`, `OIDC_ISSUER`, dan `OIDC_AUDIENCE`, matikan token dev, dan gunakan TLS di ingress. JWT akses harus memiliki `iss`, `aud`, `sub`, serta masa berlaku yang sesuai. Konfigurasi OIDC tidak menambahkan login UI; pengguna memperoleh token dari penyedia identitas.

## API

| Method dan path | Akses | Fungsi |
| --- | --- | --- |
| `POST /v1/namespaces` | Pengguna login | Buat namespace dan menjadi admin |
| `PUT /v1/namespaces/{ns}/members/{sub}` | Admin | Atur role `reader`, `publisher`, atau `admin` |
| `POST /v1/namespaces/{ns}/skills/{skill}/versions/{version}` | Publisher | Upload ZIP, scan, karantina |
| `POST /v1/namespaces/{ns}/skills/{skill}/versions/{version}/approve` | Admin | Publikasikan jika scan tanpa temuan |
| `GET /v1/namespaces/{ns}/skills` | Anggota | Daftar versi dan hasil scan |
| `GET /v1/namespaces/{ns}/skills/{skill}/versions/{version}` | Anggota | Unduh versi published |
| `GET /v1/namespaces/{ns}/audit` | Admin | 100 audit event terbaru |
| `POST /v1/namespaces/{ns}/usage` | Anggota | Kirim metrik pemanggilan skill |
| `GET /v1/namespaces/{ns}/usage` | Admin | Ringkasan penggunaan 30 hari |
| `GET /v1/mode`, `GET /healthz` | Publik | Status mode dan health |

Contoh kirim usage setelah agen memakai skill yang sudah published:

```sh
curl -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"skill":"example","version":"1.0.0","latency_ms":850,"success":true,"estimated_tokens_saved":120,"estimated_cost_usd":0.0024}' \
  http://127.0.0.1:8080/v1/namespaces/platform/usage
  
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/v1/namespaces/platform/usage
```

Telemetry dicatat oleh klien. Success rate dan latency berasal dari event klien; token dan biaya adalah **estimasi yang dilaporkan klien**, bukan ROI terverifikasi. Aplikasi agen perlu memanggil API usage; pengunduhan paket bukan pemanggilan skill.

## Scanning dan batas keamanan

Paket ZIP dibatasi 10 MiB terkompresi, 8 MiB terurai, 2 MiB per file, dan 128 entri; traversal, symlink, dan nama duplikat ditolak. Hasil scan berisi skor, temuan, dan cakupan: pola prompt injection dalam Markdown/teks, pola kode berisiko dalam Python/Bash/JavaScript/Go, serta pola dependency tidak terpin atau sumber HTTP. Temuan apa pun menahan persetujuan; admin meninjau hasil sebelum publikasi.

Scanner ini adalah **analisis statis berbasis aturan**. Ia belum memiliki feed CVE, SAST penuh, analisis aliran data, deteksi prompt injection semantik, atau jaminan pembatasan network/file system saat script kelak dijalankan. Tidak ada script skill yang dieksekusi oleh registry. Jangan memakai skor sebagai sertifikasi keamanan. Untuk memenuhi pemindaian kerentanan dependency secara menyeluruh, integrasikan scanner yang memiliki database advisori dan jadwal pembaruannya sebelum produksi.

Berkas ZIP dan metadata tersimpan dalam PostgreSQL (`bytea`). Untuk beban besar, pindahkan blob ke penyimpanan S3 kompatibel dan terapkan backup serta retensi. Audit log masih berada dalam database yang sama dan belum tahan manipulasi. Rate limiting, pagination, migrasi schema berversi, dan UI belum tersedia.

## Deployment

`deploy/k8s/registry.yaml` adalah contoh Deployment dan Service. Ganti image dan buat Secret `artificial-registry-config` yang berisi `DATABASE_URL`, `AUTH_MODE=oidc`, `OIDC_ISSUER`, dan `OIDC_AUDIENCE`. Sediakan PostgreSQL secara terpisah serta ingress TLS. Image tidak membutuhkan environment variable lisensi.

Jalankan `go test ./...` memakai Go 1.23 dan `docker compose up --build` untuk uji integrasi. Core service 2 belum termasuk versi ini.
