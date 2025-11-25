"""
Cowrie Honeypot - Gelişmiş Analiz Scripti
İsteğe bağlı derinlemesine analizler
"""

import json
import glob
import os
from datetime import datetime
from collections import Counter, defaultdict
import pandas as pd

class AdvancedCowrieAnalyzer:
    def __init__(self, log_dir):
        self.log_dir = log_dir
        self.events = []
        self.load_logs()
    
    def load_logs(self):
        """JSON log dosyalarını yükle"""
        json_files = glob.glob(os.path.join(self.log_dir, "*.json*"))
        
        for file_path in json_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            event = json.loads(line.strip())
                            self.events.append(event)
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                continue
        
        print(f"✓ {len(self.events)} event yüklendi")
    
    def analyze_session_duration(self):
        """Oturum sürelerini analiz et"""
        print("\n" + "="*80)
        print("OTURUM SÜRE ANALİZİ")
        print("="*80)
        
        durations = []
        for event in self.events:
            if event.get('eventid') == 'cowrie.session.closed':
                try:
                    duration = float(event.get('duration', 0))
                    durations.append(duration)
                except:
                    continue
        
        if durations:
            df = pd.DataFrame({'duration': durations})
            print(f"\nToplam Oturum Sayısı: {len(durations):,}")
            print(f"Ortalama Süre: {df['duration'].mean():.2f} saniye")
            print(f"Medyan Süre: {df['duration'].median():.2f} saniye")
            print(f"En Kısa Oturum: {df['duration'].min():.2f} saniye")
            print(f"En Uzun Oturum: {df['duration'].max():.2f} saniye")
            print(f"Toplam Süre: {df['duration'].sum():.2f} saniye ({df['duration'].sum()/3600:.2f} saat)")
            
            print("\nSüre Dağılımı:")
            print(f"  0-1 saniye: {len(df[df['duration'] <= 1]):,} oturum")
            print(f"  1-5 saniye: {len(df[(df['duration'] > 1) & (df['duration'] <= 5)]):,} oturum")
            print(f"  5-10 saniye: {len(df[(df['duration'] > 5) & (df['duration'] <= 10)]):,} oturum")
            print(f"  10-30 saniye: {len(df[(df['duration'] > 10) & (df['duration'] <= 30)]):,} oturum")
            print(f"  30+ saniye: {len(df[df['duration'] > 30]):,} oturum")
    
    def analyze_successful_attacks(self):
        """Başarılı saldırıları detaylı analiz et"""
        print("\n" + "="*80)
        print("BAŞARILI SALDIRI ANALİZİ")
        print("="*80)
        
        successful_logins = defaultdict(list)
        
        for event in self.events:
            if event.get('eventid') == 'cowrie.login.success':
                ip = event.get('src_ip')
                username = event.get('username')
                password = event.get('password')
                timestamp = event.get('timestamp')
                
                successful_logins[ip].append({
                    'username': username,
                    'password': password,
                    'timestamp': timestamp
                })
        
        print(f"\nBaşarılı Login Yapan Benzersiz IP: {len(successful_logins)}")
        print(f"Toplam Başarılı Login: {sum(len(v) for v in successful_logins.values())}")
        
        # En başarılı IP'ler
        print("\nEn Çok Başarılı Login Yapan IP'ler:")
        sorted_ips = sorted(successful_logins.items(), key=lambda x: len(x[1]), reverse=True)
        for i, (ip, logins) in enumerate(sorted_ips[:10], 1):
            print(f"  {i:2d}. {ip:20s} - {len(logins):,} başarılı login")
            # İlk 3 kimlik bilgisini göster
            creds = set((l['username'], l['password']) for l in logins)
            for j, (user, pwd) in enumerate(list(creds)[:3], 1):
                print(f"       └─ {user}:{pwd}")
    
    def analyze_commands(self):
        """Çalıştırılan komutları analiz et"""
        print("\n" + "="*80)
        print("KOMUT ANALİZİ")
        print("="*80)
        
        commands = Counter()
        command_by_ip = defaultdict(list)
        
        for event in self.events:
            if event.get('eventid') == 'cowrie.command.input':
                cmd = event.get('input', '').strip()
                ip = event.get('src_ip')
                if cmd:
                    commands[cmd] += 1
                    command_by_ip[ip].append(cmd)
        
        if commands:
            print(f"\nToplam Komut Sayısı: {sum(commands.values()):,}")
            print(f"Benzersiz Komut: {len(commands):,}")
            
            print("\nEn Çok Çalıştırılan Komutlar (Top 20):")
            for i, (cmd, count) in enumerate(commands.most_common(20), 1):
                # Komut çok uzunsa kısalt
                display_cmd = cmd if len(cmd) <= 60 else cmd[:57] + "..."
                print(f"  {i:2d}. [{count:4d}x] {display_cmd}")
            
            # Komut türlerini kategorize et
            download_cmds = sum(1 for cmd in commands if any(x in cmd.lower() for x in ['wget', 'curl', 'download']))
            scan_cmds = sum(1 for cmd in commands if any(x in cmd.lower() for x in ['nmap', 'scan', 'netstat']))
            info_cmds = sum(1 for cmd in commands if any(x in cmd.lower() for x in ['uname', 'whoami', 'pwd', 'ls', 'cat']))
            
            print(f"\nKomut Kategorileri:")
            print(f"  İndirme komutları: {download_cmds:,}")
            print(f"  Tarama komutları: {scan_cmds:,}")
            print(f"  Bilgi toplama: {info_cmds:,}")
        else:
            print("\nKomut verisi bulunamadı.")
    
    def analyze_download_attempts(self):
        """İndirme denemelerini analiz et"""
        print("\n" + "="*80)
        print("DOSYA İNDİRME ANALİZİ")
        print("="*80)
        
        downloads = []
        
        for event in self.events:
            if event.get('eventid') == 'cowrie.session.file_download':
                downloads.append({
                    'url': event.get('url'),
                    'outfile': event.get('outfile'),
                    'shasum': event.get('shasum'),
                    'ip': event.get('src_ip')
                })
        
        if downloads:
            print(f"\nToplam İndirme Denemesi: {len(downloads)}")
            
            # URL'lere göre grupla
            urls = Counter(d['url'] for d in downloads if d.get('url'))
            print(f"\nBenzersiz URL: {len(urls)}")
            
            print("\nEn Çok İndirilen URL'ler (Top 10):")
            for i, (url, count) in enumerate(urls.most_common(10), 1):
                display_url = url if len(url) <= 70 else url[:67] + "..."
                print(f"  {i:2d}. [{count:2d}x] {display_url}")
            
            # SHA hash'lere göre
            hashes = Counter(d['shasum'] for d in downloads if d.get('shasum'))
            print(f"\nBenzersiz Dosya (SHA): {len(hashes)}")
        else:
            print("\nDosya indirme verisi bulunamadı.")
    
    def analyze_direct_tcpip(self):
        """Direct TCP/IP forward isteklerini analiz et"""
        print("\n" + "="*80)
        print("DIRECT TCP/IP FORWARD ANALİZİ")
        print("="*80)
        
        forward_requests = []
        
        for event in self.events:
            if event.get('eventid') == 'cowrie.direct-tcpip.request':
                forward_requests.append({
                    'dst_ip': event.get('dst_ip'),
                    'dst_port': event.get('dst_port'),
                    'src_ip': event.get('src_ip')
                })
        
        if forward_requests:
            print(f"\nToplam Forward İsteği: {len(forward_requests):,}")
            
            # Hedef IP'ler
            dst_ips = Counter(r['dst_ip'] for r in forward_requests)
            print(f"\nEn Çok Hedeflenen IP'ler (Top 10):")
            for i, (ip, count) in enumerate(dst_ips.most_common(10), 1):
                print(f"  {i:2d}. {ip:40s} - {count:,} istek")
            
            # Hedef portlar
            dst_ports = Counter(r['dst_port'] for r in forward_requests)
            print(f"\nEn Çok Hedeflenen Portlar:")
            for i, (port, count) in enumerate(dst_ports.most_common(10), 1):
                print(f"  {i:2d}. Port {port:5d} - {count:,} istek")
        else:
            print("\nDirect TCP/IP forward verisi bulunamadı.")
    
    def analyze_ssh_versions(self):
        """SSH versiyonlarını detaylı analiz et"""
        print("\n" + "="*80)
        print("SSH CLIENT VERSİYON ANALİZİ")
        print("="*80)
        
        versions = Counter()
        version_by_ip = defaultdict(set)
        
        for event in self.events:
            if event.get('eventid') == 'cowrie.client.version':
                version = event.get('version', 'unknown')
                ip = event.get('src_ip')
                versions[version] += 1
                version_by_ip[ip].add(version)
        
        if versions:
            print(f"\nToplam SSH Bağlantısı: {sum(versions.values()):,}")
            print(f"Benzersiz SSH Client: {len(versions)}")
            
            # Kategori analizi
            openssh = sum(count for ver, count in versions.items() if 'OpenSSH' in ver)
            libssh = sum(count for ver, count in versions.items() if 'libssh' in ver)
            go_clients = sum(count for ver, count in versions.items() if 'Go' in ver)
            python = sum(count for ver, count in versions.items() if 'Python' in ver or 'paramiko' in ver)
            
            print(f"\nClient Türleri:")
            print(f"  OpenSSH: {openssh:,} ({openssh/sum(versions.values())*100:.1f}%)")
            print(f"  libssh: {libssh:,} ({libssh/sum(versions.values())*100:.1f}%)")
            print(f"  Go-based: {go_clients:,} ({go_clients/sum(versions.values())*100:.1f}%)")
            print(f"  Python-based: {python:,} ({python/sum(versions.values())*100:.1f}%)")
            
            # Çok client kullanan IP'ler (botnet göstergesi)
            multi_client_ips = [(ip, len(clients)) for ip, clients in version_by_ip.items() if len(clients) > 1]
            multi_client_ips.sort(key=lambda x: x[1], reverse=True)
            
            if multi_client_ips:
                print(f"\nÇoklu Client Kullanan IP'ler (Botnet göstergesi): {len(multi_client_ips)}")
                print("Top 10:")
                for i, (ip, count) in enumerate(multi_client_ips[:10], 1):
                    print(f"  {i:2d}. {ip:20s} - {count} farklı client")
    
    def generate_detailed_report(self, output_file='gelismis_analiz_raporu.txt'):
        """Detaylı rapor oluştur"""
        print("\n" + "="*80)
        print("DETAYLI RAPOR OLUŞTURULUYOR...")
        print("="*80)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("COWRIE HONEYPOT - GELİŞMİŞ ANALİZ RAPORU\n")
            f.write("="*80 + "\n\n")
            
            # Event türleri istatistikleri
            event_types = Counter(e.get('eventid', 'unknown') for e in self.events)
            
            f.write("EVENT TÜRÜ İSTATİSTİKLERİ\n")
            f.write("-"*80 + "\n")
            for event_type, count in event_types.most_common(30):
                f.write(f"{event_type:50s} : {count:,}\n")
            
            f.write("\n" + "="*80 + "\n")
            f.write(f"Rapor Tarihi: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n")
        
        print(f"\n✓ Detaylı rapor kaydedildi: {output_file}")


def main():
    print("="*80)
    print("COWRIE HONEYPOT - GELİŞMİŞ ANALİZ")
    print("="*80)
    
    log_dir = os.path.join(os.path.dirname(__file__), 'cowrie')
    
    if not os.path.exists(log_dir):
        print(f"\nHATA: '{log_dir}' klasörü bulunamadı!")
        return
    
    print("\nLoglar yükleniyor...")
    analyzer = AdvancedCowrieAnalyzer(log_dir)
    
    # Tüm analizleri çalıştır
    analyzer.analyze_session_duration()
    analyzer.analyze_successful_attacks()
    analyzer.analyze_commands()
    analyzer.analyze_download_attempts()
    analyzer.analyze_direct_tcpip()
    analyzer.analyze_ssh_versions()
    analyzer.generate_detailed_report()
    
    print("\n" + "="*80)
    print("ANALİZ TAMAMLANDI!")
    print("="*80)


if __name__ == "__main__":
    main()
