# eBPF Outbound Logger for Hosting Servers

Linux sunucularda **hangi process hangi IP’ye bağlantı açıyor** bilgisini tespit eden **eBPF tabanlı outbound connection logger**.

Hosting firmaları, SIEM projeleri, SOC ekipleri ve güvenlik analizleri için tasarlanmıştır.

Script;

- outbound TCP bağlantıları kernel seviyesinde yakalar
- process bilgisi ile ilişkilendirir
- JSON veya CSV olarak log üretir
- rsyslog üzerinden uzak SIEM sistemlerine gönderebilir
- cPanel, Plesk, DirectAdmin veya plain Linux fark etmeden çalışır

Tamamen ücretsizdir. İsteyen indirip geliştirebilir.

---

# Özellikler

- eBPF tabanlı (kernel level visibility)
- process, user, pid, command bilgisi içerir
- DNS / SNI best-effort hostname enrichment
- IPv4 ve IPv6 destekler
- JSON veya CSV log formatı
- dosyaya yazma desteği
- uzak syslog gönderme desteği
- hem local log hem SIEM gönderimi aynı anda yapılabilir
- loopback ignore opsiyonu
- private IP ignore opsiyonu
- root process ignore opsiyonu
- systemd service olarak çalışır
- uninstall desteği içerir

---

# Neden gerekli?

Hosting sunucularında aşağıdaki durumlar sıklıkla görülür:

- zararlı script dış IP'lere bağlantı açar
- spam botları SMTP sunucularına bağlanır
- webshell dış C2 server’a bağlanır
- kullanıcı scripti API abuse yapar
- compromised kullanıcı hesabı outbound trafik üretir

Bu araç sayesinde:

hangi user hangi process ile hangi IP’ye bağlanmış görülebilir.

Örnek log:

```json
{
  "timestamp": "2026-04-08T07:50:00.807018+00:00",
  "hostname": "hosting.trnog.net",
  "uid": 0,
  "user": "trnog",
  "pid": 680968,
  "comm": "curl",
  "cmdline": "curl -k https://google.com",
  "family": "ipv4",
  "src_ip": "172.16.16.1",
  "src_port": 55964,
  "dst_ip": "172.217.18.174",
  "dst_port": 443
  "dst_host": "google.com",
  "dst_host_source": "dns"
}
```

---

# Desteklenen sistemler

- AlmaLinux 8 / 9
- Rocky Linux 8 / 9
- RHEL 8 / 9
- Ubuntu 20 / 22 / 24
- Debian 11 / 12

Hosting panelleri:

- cPanel
- Plesk
- DirectAdmin
- CyberPanel
- ISPConfig
- panel olmayan Linux sistemleri

---

# Kurulum

Tek komut ile kurulum:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/TRNOG/hosting-outbound-logger/main/install.sh) install
```

veya

```bash
curl -fsSL -o install.sh https://raw.githubusercontent.com/TRNOG/hosting-outbound-logger/main/install.sh
chmod +x install.sh
./install.sh install
```

Script kurulum sırasında sorular sorar:

- log formatı (json / csv)
- dosyaya yazılsın mı
- uzak syslog gönderilsin mi
- loopback bağlantılar ignore edilsin mi
- private IP ignore edilsin mi
- root process ignore edilsin mi

---

<img width="509" height="188" alt="image" src="https://github.com/user-attachments/assets/53eed95f-c84c-40d7-9e45-dcdb0d5212e4" />

---
# Kaldırma (Uninstall)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/TRNOG/hosting-outbound-logger/main/install.sh) uninstall
```

veya

```bash
wget -O install.sh https://raw.githubusercontent.com/TRNOG/hosting-outbound-logger/main/install.sh
chmod +x install.sh
./install.sh uninstall
```

Uninstall:

- systemd service kaldırılır
- rsyslog config kaldırılır
- python logger kaldırılır
- log klasörü isteğe bağlı silinir

rsyslog veya python paketleri kaldırılmaz.

---

# Çalışma mantığı

Script kernel fonksiyonlarını hook eder:

```
tcp_v4_connect
tcp_v6_connect
```

Her bağlantı için şu bilgiler elde edilir:

- user id
- username
- process id
- process name
- command line
- source IP
- destination IP
- destination port
- timestamp

---

# Hostname enrichment

İsteğe bağlı olarak `getaddrinfo()` ve OpenSSL SNI üzerinden hedef host/domain bilgisi loglara eklenebilir.

- `dst_host_source: "dns"` → host bilgisi resolver çağrısından geldi
- `dst_host_source: "sni"` → host bilgisi TLS SNI üzerinden geldi

Bu alanlar best-effort'tür ve %100 garanti değildir.

---

# Log lokasyonu

Varsayılan:

```
/var/log/outbound-logger/YYYY-MM-DD.jsonl
```

---

# Servis yönetimi

Servis adı:

```
outbound-logger
```

Durum kontrolü:

```bash
systemctl status outbound-logger
```

yeniden başlatma:

```bash
systemctl restart outbound-logger
```

log izleme:

```bash
journalctl -u outbound-logger -f
```

dosya log izleme:

```bash
tail -f /var/log/outbound-logger/$(date +%F).jsonl
```

---

# Test

örnek outbound bağlantı oluştur:

```bash
curl https://google.com
```

veya:

```bash
curl https://1.1.1.1
```

---

# SIEM entegrasyonu

rsyslog üzerinden aşağıdaki sistemlere gönderilebilir:

- Splunk
- Elastic
- Graylog
- Wazuh
- QRadar
- Sentinel
- Custom SIEM

---

# Güvenlik notu

Bu araç:

- network packet capture yapmaz
- payload kaydetmez
- sadece metadata loglar
- tam URL / path üretmez
- varsa best-effort host/domain enrichment üretir

performans etkisi düşüktür.

---

# Katkı

Pull request kabul edilir.

Fork edip geliştirebilirsiniz.

Önerilen geliştirmeler:

- UDP connect loglama
- DNS query loglama
- process whitelist
- port filter
- geoip enrichment
- threat intel enrichment
- docker container detection
- Kubernetes destekleri

---

# Lisans

MIT License

Ücretsiz kullanılabilir ve değiştirilebilir.

---

# Proje

Doğuş ŞEKERCİ
