# Cowrie Honeypot Log Analizi
## Ağ Güvenliği ve Analizi Dersi - Yüksek Lisans Projesi

---

## 📊 Proje Özeti

Bu proje, Cowrie SSH/Telnet honeypot sistemi üzerinden toplanan gerçek saldırı loglarının kapsamlı analizini içermektedir. Honeypot, siber saldırganların davranışlarını izlemek ve saldırı tekniklerini anlamak için kullanılmıştır.

---

## 🎯 Analiz Sonuçları - Temel Bulgular

### Genel İstatistikler
- **Toplam Event:** 494,741
- **Benzersiz Saldırgan IP:** 5,018
- **Toplam Oturum:** 78,337
- **Login Denemesi:** 69,734
- **Başarılı Login:** 25,247 (36.20%)
- **Başarısız Login:** 44,487 (63.80%)

---

## 🔍 Önemli Bulgular

### 1. En Çok Hedeflenen Kullanıcı Adları
1. **root** - 25,832 deneme (Sistem yöneticisi hesabı)
2. **345gs5662d34** - 8,164 deneme (Bot/automated attack)
3. **admin** - 2,340 deneme
4. **user** - 1,516 deneme
5. **test** - 711 deneme

**Analiz:** Saldırganlar öncelikle yönetici yetkisine sahip hesapları hedefliyor. "root" hesabı tüm denemelerin %37'sini oluşturuyor.

### 2. En Çok Kullanılan Şifreler
1. **345gs5662d34** - 8,164 deneme
2. **3245gs5662d34** - 8,106 deneme
3. **123456** - 4,273 deneme
4. **admin** - 1,674 deneme
5. **123** - 1,524 deneme
6. **Ctyun@2025** - 747 deneme

**Analiz:** 
- Basit sayısal şifreler hala en popüler
- Otomatik botlar özel pattern'ler kullanıyor
- Bulut servis sağlayıcı default şifreleri hedefleniyor (Ctyun@2025)

### 3. Başarılı Saldırı Oranı
- **%36.20** başarı oranı, honeypot'un saldırganları içeri çekmek için kasıtlı olarak zayıf parolaları kabul ettiğini gösteriyor
- En başarılı kimlik bilgisi: **root:Ctyun@2025**

---

## 🌍 Saldırı Kaynakları

### En Aktif 10 Saldırgan IP
Detaylı IP listesi analiz raporunda mevcuttur. Saldırılar dünya genelinden geliyor:
- Çin
- Rusya
- ABD
- Avrupa
- Diğer Asya ülkeleri

---

## 🛠️ Kullanılan SSH Client'lar

### Popüler SSH Client Versiyonları
1. **SSH-2.0-libssh2_1.11.1** - Modern bot yazılımları
2. **SSH-2.0-OpenSSH_7.4** - Eski OpenSSH versiyonları
3. **SSH-2.0-Go** - Go dilinde yazılmış botlar
4. **SSH-2.0-libssh_0.11.1** - libssh kütüphanesi

**Analiz:** Saldırganlar çoğunlukla otomatik bot yazılımları ve scriptler kullanıyor.

---

## ⏰ Zaman Bazlı Analizler

### Saatlik Dağılım
- Saldırılar 7/24 devam ediyor
- Belirgin bir "sessiz saat" yok
- Bu, otomatik botların sürekli aktif olduğunu gösteriyor

### Günlük Trend
- Saldırılar sürekli ve kararlı
- Bazı günlerde ani artışlar görülüyor (botnet kampanyaları)

---

## 📈 Oluşturulan Grafikler

1. **01_genel_istatistikler.png** - Genel istatistiklerin bar grafiği
2. **02_login_credentials.png** - En çok kullanılan kullanıcı adı ve şifreler
3. **03_login_success_rate.png** - Başarılı vs başarısız login oranları (pasta grafiği)
4. **04_top_attacker_ips.png** - En aktif saldırgan IP adresleri
5. **05_ssh_clients.png** - SSH client versiyonları dağılımı
6. **06_time_patterns.png** - Saatlik ve günlük saldırı patternleri
7. **07_event_types.png** - Event türlerinin dağılımı

---

## 🔐 Güvenlik Önerileri

### 1. Şifre Güvenliği
- ❌ Basit şifreler kullanmayın (123456, admin, password)
- ✅ En az 12 karakter, karışık karakterler
- ✅ Şifre yöneticisi kullanın

### 2. SSH Güvenliği
- ✅ SSH key authentication kullanın
- ✅ Root login'i devre dışı bırakın
- ✅ Fail2ban gibi araçlar kullanın
- ✅ Default port'u (22) değiştirin
- ✅ 2FA (Two-Factor Authentication) aktif edin

### 3. Sistem Güvenliği
- ✅ Default kullanıcı adlarını değiştirin
- ✅ Güncel sistem kullanın
- ✅ Güvenlik yamalarını düzenli uygulayın
- ✅ Sadece gerekli portları açık tutun

### 4. Monitoring
- ✅ Log monitoring sistemleri kurun
- ✅ Anormal aktiviteleri tespit edin
- ✅ IDS/IPS sistemleri kullanın

---

## 📚 Teknik Detaylar

### Honeypot Sistemi
- **Platform:** Cowrie (SSH/Telnet Honeypot)
- **Protokol:** SSH (Port 2222)
- **Toplam Log Dosyası:** 25 adet
- **Log Formatı:** JSON + Text
- **Analiz Dönemi:** Ekim-Kasım 2025

### Analiz Araçları
- **Dil:** Python 3.14
- **Kütüphaneler:** 
  - matplotlib - Grafik görselleştirme
  - seaborn - İstatistiksel grafikler
  - pandas - Veri analizi
  - numpy - Numerik hesaplamalar

---

## 🎓 Akademik Değer

Bu analiz aşağıdaki konularda önemli bilgiler sağlıyor:

1. **Saldırı Teknikleri:** Brute-force, dictionary attack, credential stuffing
2. **Saldırgan Profili:** Otomatik botlar, script kiddies, organize gruplar
3. **Hedef Seçimi:** Yönetici hesapları, default credentials
4. **Saldırı Zamanlaması:** Sürekli, otomatik, koordineli
5. **Araçlar ve Teknikler:** Libssh, OpenSSH, custom botlar

---

## 📝 Sonuç ve Değerlendirme

### Ana Bulgular
1. **Yoğun Brute-Force Saldırıları:** Dakikada onlarca deneme
2. **Otomatik Botlar Hakimiyeti:** İnsan müdahalesi minimum
3. **Zayıf Şifreler Hedefte:** Basit kombinasyonlar çok deneniyor
4. **Global Tehdit:** Dünyanın her yerinden saldırı geliyor
5. **7/24 Aktivite:** Hiç durmayan saldırı trafiği

### Önerilen Savunma Stratejisi
1. **Proaktif Güvenlik:** Honeypot'lar ile tehdit istihbaratı
2. **Güçlü Kimlik Doğrulama:** SSH key + 2FA
3. **Sürekli İzleme:** Log analizi ve anomali tespiti
4. **Düzenli Güncelleme:** Sistem ve yazılım yamaları
5. **Eğitim:** Kullanıcı farkındalığı ve güvenlik kültürü

---

## 📁 Dosya Yapısı

```
elif-cowrie/
├── cowrie/                          # Ham log dosyaları
│   ├── cowrie.json                  # JSON formatında loglar
│   ├── cowrie.json.2025-*           # Tarihli JSON logları
│   └── cowrie.log.2025-*            # Tarihli text logları
├── graphs/                          # Oluşturulan grafikler
│   ├── 01_genel_istatistikler.png
│   ├── 02_login_credentials.png
│   ├── 03_login_success_rate.png
│   ├── 04_top_attacker_ips.png
│   ├── 05_ssh_clients.png
│   ├── 06_time_patterns.png
│   └── 07_event_types.png
├── analyze_cowrie_logs.py           # Ana analiz scripti
├── requirements.txt                 # Python bağımlılıkları
├── cowrie_analiz_raporu.txt         # Detaylı metin raporu
└── README.md                        # Bu dosya
```

---

## 🚀 Kullanım

### Kurulum
```bash
# Virtual environment oluştur
py -m venv venv

# Virtual environment'ı aktif et
.\venv\Scripts\Activate.ps1

# Gerekli kütüphaneleri kur
pip install -r requirements.txt
```

### Analizi Çalıştırma
```bash
python analyze_cowrie_logs.py
```

### Çıktılar
- `graphs/` klasöründe 7 adet yüksek çözünürlüklü grafik (300 DPI)
- `cowrie_analiz_raporu.txt` detaylı metin raporu

---

## 👨‍🎓 Proje Bilgileri

- **Ders:** Ağ Güvenliği ve Analizi
- **Seviye:** Yüksek Lisans
- **Konu:** Honeypot Log Analizi ve Siber Saldırı Patternleri
- **Tarih:** Kasım 2025

---

## 📊 Sunumda Kullanım Önerileri

### Slayt Yapısı Önerisi

1. **Giriş Slaytı**
   - Honeypot nedir?
   - Cowrie honeypot tanıtımı
   - Proje amacı

2. **Metodoloji**
   - Veri toplama süreci
   - Analiz araçları
   - Zaman periyodu

3. **Genel İstatistikler**
   - Grafik: 01_genel_istatistikler.png
   - Temel sayılar ve trendler

4. **Saldırgan Profili**
   - Grafik: 04_top_attacker_ips.png
   - Coğrafi dağılım
   - Saldırı yoğunluğu

5. **Kullanılan Kimlik Bilgileri**
   - Grafik: 02_login_credentials.png
   - En popüler kombinasyonlar
   - Password pattern analizi

6. **Başarı Oranları**
   - Grafik: 03_login_success_rate.png
   - Başarılı/başarısız login oranları
   - Honeypot'un çekiciliği

7. **Saldırı Araçları**
   - Grafik: 05_ssh_clients.png
   - Kullanılan SSH client'lar
   - Bot yazılımları

8. **Zaman Patternleri**
   - Grafik: 06_time_patterns.png
   - Saatlik dağılım
   - Günlük trendler
   - 7/24 aktivite

9. **Event Analizi**
   - Grafik: 07_event_types.png
   - Hangi aktiviteler gerçekleşti?
   - Saldırı senaryoları

10. **Güvenlik Önerileri**
    - Bulgulardan çıkarılan dersler
    - Pratik güvenlik önerileri
    - Kurumsal savunma stratejileri

11. **Sonuç**
    - Özet bulgular
    - Gelecek çalışmalar
    - Sorular

---

## 🔗 Ek Kaynaklar

- [Cowrie Honeypot](https://github.com/cowrie/cowrie) - Resmi GitHub repo
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Web güvenliği
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) - Güvenlik çerçevesi

---

## ⚠️ Yasal Uyarı

Bu proje sadece eğitim ve araştırma amaçlıdır. Honeypot sistemleri yalnızca kendi ağınızda, yasal izinlerle kurulmalıdır. Elde edilen veriler etik kurallara uygun şekilde kullanılmalıdır.

---

**Hazırlayan:** Elif  
**Tarih:** Kasım 2025  
**Ders:** Ağ Güvenliği ve Analizi (Yüksek Lisans)
