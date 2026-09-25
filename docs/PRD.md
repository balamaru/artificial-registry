# Artificial Registry

> Scope implementasi uji awal: core services 1 dan 3 tersedia gratis tanpa license key, termasuk fitur yang awalnya berlabel Enterprise. Core service 2 dikecualikan. Lihat README dan docs/operations.md untuk fitur yang tersedia serta batas implementasi.

## 1. Ringkasan
Product registry yang ada saat ini berperan untuk menyimpan docker image ataupun hasil build baik dari node, golang, rust, dsb. Namun dengan berkembangnya AI saat ini banyak company yang melakukan coding dengan bantuan AI Agent (Vibe Coding), untuk memperoleh kemampuan yang lebih optimum agent-agent AI yang diperintahkan untuk melakukan coding diberikan skill - skill yang sesuai dengan kebutuhan, seperti hasil build node atau hasil build image, tidak semuanya bisa dipublish secara publik, karena ini merupakan core/service suatu perusahaan yang memang mendukung sisi bisnisnya (agar model bisnis tidak bocor keluar). Saat ini ada beberapa Registry Ai Skill yang tersedia seperti Google Cloud Agent Registry berbasis Managed cloud ataupun SkillHub by iFlyTek untuk self hosted.

Existing agent skill registry khususnya yang self hosted masih punya kekurangan, dengan itu akan mengusung untuk create AI Skill Registry sendiri dengan basis self hosted.

## 2. Konsep
- Container based (sehingga bisa dijalankan via docker atau kubernetes (kubernetes recomended), lengkap dengan Namespace, OAuth, Audit Log)
- Lighweight Microservice (dengan golang disarankan)
- Storage external (PostgreSQL atau S3 (bisa minio, Silio, atau RustFS)
- Security Scanning

## 3. Architecture 
- Artificial Registry (yang akan dibangun)
- PostgreSQL

## 4. Core services
1. Automated Security & Prompt Injection Scanning
Registry biasa hanya mengecek apakah berkas zip/tar valid. Registry ini bisa bertindak sebagai security gateway:
- Static Analysis for Skills: Menguji instruksi SKILL.md atau prompt terhadap jailbreak attempt, indirect prompt injection, atau instruksi tersembunyi yang berbahaya.
- Code & Dependency Scanning: Jika skill menyertakan executable script (Python/Bash), lakukan pemindaian kerentanan (SAST) dan cek apakah script mencoba mengakses network/file system di luar scope. (Enterprise Mode)
- Skill Trust Score: Setiap skill diberikan skor keamanan sebelum di-publish ke registry internal. (Enterprise mode)

2. Runtime Evaluation & Dry-Run Sandbox (Enterprise Mode)
Alih-alih cuma menyimpan file, sediakan fitur Dry-Run Test Environment:
- Sebelum skill disetujui (approved) oleh Tim Lead/Security, registry menyediakan opsi one-click test sandbox.
- Tim bisa melihat bagaimana agen (misal menggunakan Claude, GPT-4o, atau LLM lokal) mengeksekusi skill tersebut dengan mock data untuk melihat apakah terjadi hallucination atau hasil yang tidak konsisten.

3. Telemetry, Usage Analytics, & ROI Tracking (Enterprise Mode)
Enterprise butuh tahu skill mana yang memberikan efisiensi nyata:
- Metrics: Seberapa sering skill A dipanggil oleh agen internal? Berapa rata-rata latency dan success rate-nya? 
- Cost Tracking: Berapa est. token / cost yang dihemat dengan menggunakan prompt/skill yang teroptimasi ini. 

# Notes
- Enterprise Mode : adalah feature full yang diberikan jika membeli lisensi
- Free Mode : hanya bisa mengakses feature yang tidak ada label enterprise mode

Sehingga dari catatan ini akan ada docker image enterprise bisa menambahkan env license, tetap bisa jalan kalaupun tanpa env ini, tetapi dalam skala free mode