"""
Cowrie Honeypot Log Analizi
Ağ Güvenliği ve Analizi Dersi
"""

import json
import glob
import os
from datetime import datetime
from collections import Counter, defaultdict
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np

# Türkçe karakter desteği
plt.rcParams['font.sans-serif'] = ['DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False

class CowrieAnalyzer:
    def __init__(self, log_dir):
        self.log_dir = log_dir
        self.events = []
        self.load_logs()
        
    def load_logs(self):
        """Tüm JSON log dosyalarını yükle"""
        json_files = glob.glob(os.path.join(self.log_dir, "*.json*"))
        print(f"Toplam {len(json_files)} log dosyası bulundu")
        
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
                print(f"Hata ({file_path}): {e}")
        
        print(f"Toplam {len(self.events)} event yüklendi")
    
    def get_statistics(self):
        """Genel istatistikler"""
        stats = {
            'total_events': len(self.events),
            'unique_ips': len(set(e.get('src_ip') for e in self.events if 'src_ip' in e)),
            'total_sessions': len(set(e.get('session') for e in self.events if 'session' in e)),
            'login_attempts': len([e for e in self.events if 'login' in e.get('eventid', '')]),
            'successful_logins': len([e for e in self.events if e.get('eventid') == 'cowrie.login.success']),
            'failed_logins': len([e for e in self.events if e.get('eventid') == 'cowrie.login.failed']),
        }
        return stats
    
    def analyze_login_attempts(self):
        """Login denemelerini analiz et"""
        login_events = [e for e in self.events if 'login' in e.get('eventid', '')]
        
        usernames = Counter()
        passwords = Counter()
        credentials = Counter()
        successful_creds = []
        
        for event in login_events:
            username = event.get('username', 'unknown')
            password = event.get('password', 'unknown')
            
            usernames[username] += 1
            passwords[password] += 1
            credentials[f"{username}:{password}"] += 1
            
            if event.get('eventid') == 'cowrie.login.success':
                successful_creds.append((username, password, event.get('src_ip')))
        
        return {
            'usernames': usernames,
            'passwords': passwords,
            'credentials': credentials,
            'successful_creds': successful_creds
        }
    
    def analyze_ip_addresses(self):
        """IP adreslerini analiz et"""
        ip_counter = Counter()
        ip_events = defaultdict(list)
        
        for event in self.events:
            src_ip = event.get('src_ip')
            if src_ip:
                ip_counter[src_ip] += 1
                ip_events[src_ip].append(event.get('eventid'))
        
        return ip_counter, ip_events
    
    def analyze_ssh_clients(self):
        """SSH client versiyonlarını analiz et"""
        clients = Counter()
        hassh = Counter()
        
        for event in self.events:
            if event.get('eventid') == 'cowrie.client.version':
                version = event.get('version', 'unknown')
                clients[version] += 1
            
            if event.get('eventid') == 'cowrie.client.kex':
                hassh_value = event.get('hassh', 'unknown')
                hassh[hassh_value] += 1
        
        return clients, hassh
    
    def analyze_time_patterns(self):
        """Zaman bazlı pattern analizi"""
        hourly_attacks = Counter()
        daily_attacks = Counter()
        
        for event in self.events:
            timestamp = event.get('timestamp')
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    hourly_attacks[dt.hour] += 1
                    daily_attacks[dt.date()] += 1
                except:
                    continue
        
        return hourly_attacks, daily_attacks
    
    def analyze_commands(self):
        """Çalıştırılan komutları analiz et"""
        commands = Counter()
        
        for event in self.events:
            if event.get('eventid') == 'cowrie.command.input':
                cmd = event.get('input', '').strip()
                if cmd:
                    commands[cmd] += 1
        
        return commands
    
    def create_visualizations(self, output_dir='graphs'):
        """Tüm grafikleri oluştur"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Renk paleti
        colors = sns.color_palette("husl", 10)
        
        # 1. Genel İstatistikler
        self.plot_general_stats(output_dir)
        
        # 2. Login Analizi
        self.plot_login_analysis(output_dir)
        
        # 3. IP Analizi
        self.plot_ip_analysis(output_dir)
        
        # 4. SSH Client Analizi
        self.plot_ssh_clients(output_dir)
        
        # 5. Zaman Bazlı Analiz
        self.plot_time_analysis(output_dir)
        
        # 6. Event Türleri
        self.plot_event_types(output_dir)
        
        print(f"\nTüm grafikler '{output_dir}' klasörüne kaydedildi!")
    
    def plot_general_stats(self, output_dir):
        """Genel istatistikler grafiği"""
        stats = self.get_statistics()
        
        fig, ax = plt.subplots(figsize=(12, 6))
        
        categories = ['Toplam\nEvent', 'Benzersiz\nIP', 'Toplam\nOturum', 
                     'Login\nDenemesi', 'Başarılı\nLogin', 'Başarısız\nLogin']
        values = [stats['total_events'], stats['unique_ips'], stats['total_sessions'],
                 stats['login_attempts'], stats['successful_logins'], stats['failed_logins']]
        
        bars = ax.bar(categories, values, color=sns.color_palette("Set2", 6))
        
        # Değerleri barların üstüne yaz
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{int(height):,}',
                   ha='center', va='bottom', fontsize=10, fontweight='bold')
        
        ax.set_ylabel('Sayı', fontsize=12, fontweight='bold')
        ax.set_title('Cowrie Honeypot Genel İstatistikler', fontsize=14, fontweight='bold', pad=20)
        ax.yaxis.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, '01_genel_istatistikler.png'), dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_login_analysis(self, output_dir):
        """Login analizi grafikleri"""
        login_data = self.analyze_login_attempts()
        
        # Top 15 Kullanıcı Adları
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
        
        top_users = login_data['usernames'].most_common(15)
        users, counts = zip(*top_users)
        
        bars1 = ax1.barh(range(len(users)), counts, color=sns.color_palette("coolwarm", len(users)))
        ax1.set_yticks(range(len(users)))
        ax1.set_yticklabels(users)
        ax1.set_xlabel('Deneme Sayısı', fontweight='bold')
        ax1.set_title('En Çok Denenen 15 Kullanıcı Adı', fontweight='bold', pad=10)
        ax1.invert_yaxis()
        
        for i, bar in enumerate(bars1):
            width = bar.get_width()
            ax1.text(width, bar.get_y() + bar.get_height()/2.,
                    f' {int(width):,}',
                    ha='left', va='center', fontsize=9)
        
        # Top 15 Şifreler
        top_passwords = login_data['passwords'].most_common(15)
        passwords, counts = zip(*top_passwords)
        
        bars2 = ax2.barh(range(len(passwords)), counts, color=sns.color_palette("viridis", len(passwords)))
        ax2.set_yticks(range(len(passwords)))
        ax2.set_yticklabels(passwords)
        ax2.set_xlabel('Deneme Sayısı', fontweight='bold')
        ax2.set_title('En Çok Denenen 15 Şifre', fontweight='bold', pad=10)
        ax2.invert_yaxis()
        
        for i, bar in enumerate(bars2):
            width = bar.get_width()
            ax2.text(width, bar.get_y() + bar.get_height()/2.,
                    f' {int(width):,}',
                    ha='left', va='center', fontsize=9)
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, '02_login_credentials.png'), dpi=300, bbox_inches='tight')
        plt.close()
        
        # Başarılı vs Başarısız Login
        fig, ax = plt.subplots(figsize=(10, 6))
        
        stats = self.get_statistics()
        login_types = ['Başarılı Login', 'Başarısız Login']
        login_counts = [stats['successful_logins'], stats['failed_logins']]
        
        colors = ['#2ecc71', '#e74c3c']
        explode = (0.1, 0)
        
        wedges, texts, autotexts = ax.pie(login_counts, labels=login_types, autopct='%1.1f%%',
                                           colors=colors, explode=explode, startangle=90,
                                           textprops={'fontsize': 12, 'fontweight': 'bold'})
        
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontsize(14)
            autotext.set_fontweight('bold')
        
        ax.set_title('Başarılı vs Başarısız Login Denemeleri', fontsize=14, fontweight='bold', pad=20)
        
        # Legend ile sayıları göster
        legend_labels = [f'{label}: {count:,}' for label, count in zip(login_types, login_counts)]
        ax.legend(legend_labels, loc='upper left', bbox_to_anchor=(1, 1))
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, '03_login_success_rate.png'), dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_ip_analysis(self, output_dir):
        """IP adres analizi"""
        ip_counter, ip_events = self.analyze_ip_addresses()
        
        # Top 20 IP adresleri
        fig, ax = plt.subplots(figsize=(12, 8))
        
        top_ips = ip_counter.most_common(20)
        ips, counts = zip(*top_ips)
        
        bars = ax.barh(range(len(ips)), counts, color=sns.color_palette("rocket", len(ips)))
        ax.set_yticks(range(len(ips)))
        ax.set_yticklabels(ips, fontsize=9)
        ax.set_xlabel('Aktivite Sayısı', fontweight='bold')
        ax.set_title('En Aktif 20 Saldırgan IP Adresi', fontweight='bold', pad=10, fontsize=14)
        ax.invert_yaxis()
        
        for i, bar in enumerate(bars):
            width = bar.get_width()
            ax.text(width, bar.get_y() + bar.get_height()/2.,
                   f' {int(width):,}',
                   ha='left', va='center', fontsize=9)
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, '04_top_attacker_ips.png'), dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_ssh_clients(self, output_dir):
        """SSH client analizi"""
        clients, hassh = self.analyze_ssh_clients()
        
        if not clients:
            print("SSH client verisi bulunamadı")
            return
        
        # Top SSH Client Versiyonları
        fig, ax = plt.subplots(figsize=(12, 8))
        
        top_clients = clients.most_common(15)
        client_names, counts = zip(*top_clients)
        
        # Client isimlerini kısalt
        short_names = []
        for name in client_names:
            if len(name) > 40:
                short_names.append(name[:37] + '...')
            else:
                short_names.append(name)
        
        bars = ax.barh(range(len(short_names)), counts, color=sns.color_palette("mako", len(short_names)))
        ax.set_yticks(range(len(short_names)))
        ax.set_yticklabels(short_names, fontsize=8)
        ax.set_xlabel('Kullanım Sayısı', fontweight='bold')
        ax.set_title('En Çok Kullanılan SSH Client Versiyonları', fontweight='bold', pad=10, fontsize=14)
        ax.invert_yaxis()
        
        for i, bar in enumerate(bars):
            width = bar.get_width()
            ax.text(width, bar.get_y() + bar.get_height()/2.,
                   f' {int(width):,}',
                   ha='left', va='center', fontsize=8)
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, '05_ssh_clients.png'), dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_time_analysis(self, output_dir):
        """Zaman bazlı analiz grafikleri"""
        hourly_attacks, daily_attacks = self.analyze_time_patterns()
        
        # Saatlik Dağılım
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 10))
        
        hours = list(range(24))
        hour_counts = [hourly_attacks.get(h, 0) for h in hours]
        
        bars = ax1.bar(hours, hour_counts, color=sns.color_palette("twilight", 24), edgecolor='black', linewidth=0.5)
        ax1.set_xlabel('Saat (UTC)', fontweight='bold')
        ax1.set_ylabel('Event Sayısı', fontweight='bold')
        ax1.set_title('Saatlik Saldırı Dağılımı', fontweight='bold', pad=10, fontsize=14)
        ax1.set_xticks(hours)
        ax1.grid(axis='y', alpha=0.3)
        
        # Günlük Dağılım
        if daily_attacks:
            sorted_days = sorted(daily_attacks.keys())
            day_counts = [daily_attacks[day] for day in sorted_days]
            day_labels = [day.strftime('%Y-%m-%d') for day in sorted_days]
            
            ax2.plot(range(len(sorted_days)), day_counts, marker='o', linewidth=2, 
                    markersize=6, color='#e74c3c')
            ax2.fill_between(range(len(sorted_days)), day_counts, alpha=0.3, color='#e74c3c')
            ax2.set_xlabel('Tarih', fontweight='bold')
            ax2.set_ylabel('Event Sayısı', fontweight='bold')
            ax2.set_title('Günlük Saldırı Trendi', fontweight='bold', pad=10, fontsize=14)
            ax2.grid(True, alpha=0.3)
            
            # X ekseni etiketleri
            if len(sorted_days) > 10:
                # Çok fazla gün varsa, bazılarını göster
                step = len(sorted_days) // 10
                indices = list(range(0, len(sorted_days), step))
                ax2.set_xticks(indices)
                ax2.set_xticklabels([day_labels[i] for i in indices], rotation=45, ha='right')
            else:
                ax2.set_xticks(range(len(sorted_days)))
                ax2.set_xticklabels(day_labels, rotation=45, ha='right')
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, '06_time_patterns.png'), dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_event_types(self, output_dir):
        """Event türlerini analiz et"""
        event_types = Counter()
        
        for event in self.events:
            event_id = event.get('eventid', 'unknown')
            event_types[event_id] += 1
        
        # Top 15 Event Türü
        fig, ax = plt.subplots(figsize=(12, 8))
        
        top_events = event_types.most_common(15)
        events, counts = zip(*top_events)
        
        # Event isimlerini kısalt (cowrie. prefix'ini kaldır)
        short_events = [e.replace('cowrie.', '') for e in events]
        
        bars = ax.barh(range(len(short_events)), counts, color=sns.color_palette("Spectral", len(short_events)))
        ax.set_yticks(range(len(short_events)))
        ax.set_yticklabels(short_events, fontsize=9)
        ax.set_xlabel('Sayı', fontweight='bold')
        ax.set_title('En Sık Görülen 15 Event Türü', fontweight='bold', pad=10, fontsize=14)
        ax.invert_yaxis()
        
        for i, bar in enumerate(bars):
            width = bar.get_width()
            ax.text(width, bar.get_y() + bar.get_height()/2.,
                   f' {int(width):,}',
                   ha='left', va='center', fontsize=9)
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, '07_event_types.png'), dpi=300, bbox_inches='tight')
        plt.close()
    
    def generate_report(self, output_file='cowrie_analiz_raporu.txt'):
        """Detaylı metin raporu oluştur"""
        stats = self.get_statistics()
        login_data = self.analyze_login_attempts()
        ip_counter, ip_events = self.analyze_ip_addresses()
        clients, hassh = self.analyze_ssh_clients()
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("COWRIE HONEYPOT ANALİZ RAPORU\n")
            f.write("Ağ Güvenliği ve Analizi Dersi\n")
            f.write("="*80 + "\n\n")
            
            f.write("1. GENEL İSTATİSTİKLER\n")
            f.write("-" * 80 + "\n")
            f.write(f"Toplam Event Sayısı: {stats['total_events']:,}\n")
            f.write(f"Benzersiz IP Adresi: {stats['unique_ips']:,}\n")
            f.write(f"Toplam Oturum: {stats['total_sessions']:,}\n")
            f.write(f"Toplam Login Denemesi: {stats['login_attempts']:,}\n")
            f.write(f"Başarılı Login: {stats['successful_logins']:,}\n")
            f.write(f"Başarısız Login: {stats['failed_logins']:,}\n")
            
            if stats['login_attempts'] > 0:
                success_rate = (stats['successful_logins'] / stats['login_attempts']) * 100
                f.write(f"Başarı Oranı: {success_rate:.2f}%\n")
            
            f.write("\n2. EN ÇOK KULLANILAN KULLANICI ADLARI (Top 20)\n")
            f.write("-" * 80 + "\n")
            for i, (username, count) in enumerate(login_data['usernames'].most_common(20), 1):
                f.write(f"{i:2d}. {username:30s} : {count:,} deneme\n")
            
            f.write("\n3. EN ÇOK KULLANILAN ŞİFRELER (Top 20)\n")
            f.write("-" * 80 + "\n")
            for i, (password, count) in enumerate(login_data['passwords'].most_common(20), 1):
                f.write(f"{i:2d}. {password:30s} : {count:,} deneme\n")
            
            f.write("\n4. EN ÇOK KULLANILAN KİMLİK BİLGİLERİ (Top 20)\n")
            f.write("-" * 80 + "\n")
            for i, (cred, count) in enumerate(login_data['credentials'].most_common(20), 1):
                f.write(f"{i:2d}. {cred:50s} : {count:,} deneme\n")
            
            f.write("\n5. BAŞARILI LOGİN DENEMELERİ\n")
            f.write("-" * 80 + "\n")
            if login_data['successful_creds']:
                for username, password, ip in login_data['successful_creds'][:50]:
                    f.write(f"Username: {username:20s} Password: {password:20s} IP: {ip}\n")
            else:
                f.write("Başarılı login denemesi bulunamadı.\n")
            
            f.write("\n6. EN AKTİF SALDIRGAN IP ADRESLERİ (Top 30)\n")
            f.write("-" * 80 + "\n")
            for i, (ip, count) in enumerate(ip_counter.most_common(30), 1):
                f.write(f"{i:2d}. {ip:20s} : {count:,} aktivite\n")
            
            f.write("\n7. SSH CLIENT VERSİYONLARI (Top 20)\n")
            f.write("-" * 80 + "\n")
            for i, (client, count) in enumerate(clients.most_common(20), 1):
                f.write(f"{i:2d}. {client:50s} : {count:,}\n")
            
            f.write("\n" + "="*80 + "\n")
            f.write("Rapor Tarihi: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n")
            f.write("="*80 + "\n")
        
        print(f"\nDetaylı rapor '{output_file}' dosyasına kaydedildi!")


def main():
    print("="*80)
    print("COWRIE HONEYPOT LOG ANALİZİ")
    print("Ağ Güvenliği ve Analizi Dersi")
    print("="*80)
    print()
    
    # Log klasörünü belirle
    log_dir = os.path.join(os.path.dirname(__file__), 'cowrie')
    
    if not os.path.exists(log_dir):
        print(f"HATA: '{log_dir}' klasörü bulunamadı!")
        return
    
    # Analiz yap
    print("Loglar yükleniyor...")
    analyzer = CowrieAnalyzer(log_dir)
    
    print("\nİstatistikler hesaplanıyor...")
    stats = analyzer.get_statistics()
    
    print("\n" + "="*80)
    print("ÖZET İSTATİSTİKLER")
    print("="*80)
    print(f"Toplam Event        : {stats['total_events']:,}")
    print(f"Benzersiz IP        : {stats['unique_ips']:,}")
    print(f"Toplam Oturum       : {stats['total_sessions']:,}")
    print(f"Login Denemesi      : {stats['login_attempts']:,}")
    print(f"Başarılı Login      : {stats['successful_logins']:,}")
    print(f"Başarısız Login     : {stats['failed_logins']:,}")
    
    if stats['login_attempts'] > 0:
        success_rate = (stats['successful_logins'] / stats['login_attempts']) * 100
        print(f"Başarı Oranı        : {success_rate:.2f}%")
    
    print("\nGrafikler oluşturuluyor...")
    analyzer.create_visualizations()
    
    print("\nDetaylı rapor hazırlanıyor...")
    analyzer.generate_report()
    
    print("\n" + "="*80)
    print("ANALİZ TAMAMLANDI!")
    print("="*80)
    print("\nOluşturulan dosyalar:")
    print("  - graphs/ klasöründe 7 adet grafik")
    print("  - cowrie_analiz_raporu.txt (detaylı metin raporu)")
    print("\nBu grafikler ve rapor sunumunuzda kullanıma hazır!")


if __name__ == "__main__":
    main()
