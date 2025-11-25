#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cowrie Honeypot - IP Harita Görselleştirmesi
Saldırgan IP adreslerini dünya haritasında gösterir
"""

import json
import glob
from collections import Counter, defaultdict
import folium
from folium.plugins import HeatMap, MarkerCluster
import requests
import time
from datetime import datetime
import pickle
import os

class IPMapVisualizer:
    def __init__(self, log_dir='cowrie'):
        self.log_dir = log_dir
        self.events = []
        self.ip_locations = {}
        self.cache_file = 'ip_geolocation_cache.pkl'
        self.geo_cache = self.load_cache()
        
    def load_logs(self):
        """JSON log dosyalarını yükle"""
        json_files = glob.glob(f'{self.log_dir}/cowrie.json*')
        print(f"📁 {len(json_files)} log dosyası bulundu")
        
        for file in json_files:
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            event = json.loads(line.strip())
                            self.events.append(event)
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                print(f"⚠️  {file} okunamadı: {e}")
        
        print(f"✅ {len(self.events):,} event yüklendi")
    
    def load_cache(self):
        """Önbelleği yükle"""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'rb') as f:
                    return pickle.load(f)
            except:
                return {}
        return {}
    
    def save_cache(self):
        """Önbelleği kaydet"""
        with open(self.cache_file, 'wb') as f:
            pickle.dump(self.geo_cache, f)
    
    def get_ip_coordinates(self, ip):
        """IP adresinin gerçek coğrafi konumunu API ile al"""
        # Önbellekte var mı kontrol et
        if ip in self.geo_cache:
            cached = self.geo_cache[ip]
            return cached['lat'], cached['lon'], cached['country'], cached['city']
        
        # Özel IP aralıklarını atla
        if ip.startswith(('10.', '172.', '192.168.', '127.', '0.')):
            return None, None, None, None
        
        try:
            # ip-api.com ücretsiz API (dakikada 45 istek limiti)
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    lat = data.get('lat')
                    lon = data.get('lon')
                    country = data.get('country', 'Unknown')
                    city = data.get('city', 'Unknown')
                    
                    # Önbelleğe kaydet
                    self.geo_cache[ip] = {
                        'lat': lat,
                        'lon': lon,
                        'country': country,
                        'city': city
                    }
                    
                    return lat, lon, country, city
            
            # Başarısız ise None döndür
            return None, None, None, None
            
        except Exception as e:
            print(f"⚠️  {ip} sorgulanamadı: {e}")
            return None, None, None, None
    
    def analyze_ips(self):
        """IP adreslerini analiz et"""
        ip_stats = defaultdict(lambda: {'count': 0, 'sessions': 0, 'logins': 0, 'commands': 0})
        
        for event in self.events:
            src_ip = event.get('src_ip')
            if not src_ip:
                continue
            
            ip_stats[src_ip]['count'] += 1
            
            eventid = event.get('eventid', '')
            if 'session.connect' in eventid:
                ip_stats[src_ip]['sessions'] += 1
            elif 'login' in eventid:
                ip_stats[src_ip]['logins'] += 1
            elif 'command' in eventid:
                ip_stats[src_ip]['commands'] += 1
        
        print(f"\n🌍 {len(ip_stats)} IP için konum bilgisi sorgulanıyor...")
        print("⏱️  Bu işlem birkaç dakika sürebilir (API limiti nedeniyle)...")
        
        # Her IP için konum bilgisi ekle
        processed = 0
        failed = 0
        
        for ip, stats in ip_stats.items():
            lat, lon, country, city = self.get_ip_coordinates(ip)
            
            if lat is not None and lon is not None:
                self.ip_locations[ip] = {
                    'lat': lat,
                    'lon': lon,
                    'country': country,
                    'city': city,
                    'count': stats['count'],
                    'sessions': stats['sessions'],
                    'logins': stats['logins'],
                    'commands': stats['commands']
                }
            else:
                failed += 1
            
            processed += 1
            
            # Her 50 IP'de bir ilerleme göster
            if processed % 50 == 0:
                print(f"  ✓ {processed}/{len(ip_stats)} IP işlendi...")
            
            # API limiti için bekleme (önbellekte yoksa)
            if ip not in self.geo_cache and lat is not None:
                time.sleep(1.4)  # Dakikada ~45 istek için güvenli bekleme
        
        # Önbelleği kaydet
        self.save_cache()
        
        print(f"\n✅ {len(self.ip_locations)} IP başarıyla konumlandırıldı")
        if failed > 0:
            print(f"⚠️  {failed} IP konumlandırılamadı")
        
        return ip_stats
    
    def create_heatmap(self, output_file='ip_heatmap.html'):
        """Isı haritası oluştur"""
        print("\n🌍 Isı haritası oluşturuluyor...")
        
        # Dünya haritası oluştur
        world_map = folium.Map(
            location=[20, 0],
            zoom_start=2,
            tiles='OpenStreetMap'
        )
        
        # Isı haritası için veri hazırla
        heat_data = []
        for ip, loc in self.ip_locations.items():
            # Aktivite sayısına göre ağırlık
            weight = min(loc['count'] / 100, 10)  # Max 10x ağırlık
            heat_data.append([loc['lat'], loc['lon'], weight])
        
        # Isı haritası ekle
        HeatMap(
            heat_data,
            min_opacity=0.3,
            max_opacity=0.8,
            radius=15,
            blur=20,
            gradient={0.4: 'blue', 0.6: 'yellow', 0.8: 'orange', 1.0: 'red'}
        ).add_to(world_map)
        
        # Kaydet
        world_map.save(output_file)
        print(f"✅ Isı haritası kaydedildi: {output_file}")
    
    def create_marker_map(self, output_file='ip_markers.html', top_n=50):
        """En aktif IP'leri işaretçilerle göster"""
        print(f"\n📍 İşaretçi haritası oluşturuluyor (Top {top_n})...")
        
        # Dünya haritası oluştur
        world_map = folium.Map(
            location=[20, 0],
            zoom_start=2,
            tiles='CartoDB positron'
        )
        
        # Marker cluster oluştur
        marker_cluster = MarkerCluster().add_to(world_map)
        
        # En aktif IP'leri al
        sorted_ips = sorted(
            self.ip_locations.items(),
            key=lambda x: x[1]['count'],
            reverse=True
        )[:top_n]
        
        # İşaretçileri ekle
        for ip, loc in sorted_ips:
            # Aktivite seviyesine göre renk
            if loc['count'] > 10000:
                color = 'red'
                icon = 'exclamation-triangle'
            elif loc['count'] > 1000:
                color = 'orange'
                icon = 'warning-sign'
            elif loc['count'] > 100:
                color = 'blue'
                icon = 'info-sign'
            else:
                color = 'green'
                icon = 'ok-sign'
            
            # Popup içeriği
            popup_html = f"""
            <div style="font-family: Arial; width: 250px;">
                <h4 style="color: {color}; margin: 5px 0;">🎯 {ip}</h4>
                <hr style="margin: 5px 0;">
                <b>🌍 Ülke:</b> {loc['country']}<br>
                <b>🏙️ Şehir:</b> {loc['city']}<br>
                <b>📍 Konum:</b> {loc['lat']:.2f}, {loc['lon']:.2f}<br>
                <hr style="margin: 5px 0;">
                <b>Toplam Aktivite:</b> {loc['count']:,}<br>
                <b>Oturumlar:</b> {loc['sessions']:,}<br>
                <b>Login Denemeleri:</b> {loc['logins']:,}<br>
                <b>Komutlar:</b> {loc['commands']:,}<br>
            </div>
            """
            
            folium.Marker(
                location=[loc['lat'], loc['lon']],
                popup=folium.Popup(popup_html, max_width=250),
                tooltip=f"{ip} - {loc['count']:,} aktivite",
                icon=folium.Icon(color=color, icon=icon, prefix='glyphicon')
            ).add_to(marker_cluster)
        
        # Kaydet
        world_map.save(output_file)
        print(f"✅ İşaretçi haritası kaydedildi: {output_file}")
    
    def create_cluster_map(self, output_file='ip_clusters.html'):
        """Tüm IP'leri kümeleme ile göster"""
        print("\n📊 Kümeleme haritası oluşturuluyor...")
        
        # Dünya haritası oluştur
        world_map = folium.Map(
            location=[20, 0],
            zoom_start=2,
            tiles='OpenStreetMap'
        )
        
        # Marker cluster oluştur
        marker_cluster = MarkerCluster(
            name='Saldırgan IP\'ler',
            overlay=True,
            control=True,
            icon_create_function=None
        ).add_to(world_map)
        
        # Tüm IP'leri ekle
        for ip, loc in self.ip_locations.items():
            # Basit popup
            popup_text = f"""
            <b>IP:</b> {ip}<br>
            <b>Ülke:</b> {loc['country']}<br>
            <b>Şehir:</b> {loc['city']}<br>
            <b>Aktivite:</b> {loc['count']:,}
            """
            
            folium.CircleMarker(
                location=[loc['lat'], loc['lon']],
                radius=3,
                popup=popup_text,
                tooltip=ip,
                color='red',
                fill=True,
                fillColor='red',
                fillOpacity=0.6
            ).add_to(marker_cluster)
        
        # Layer control ekle
        folium.LayerControl().add_to(world_map)
        
        # Kaydet
        world_map.save(output_file)
        print(f"✅ Kümeleme haritası kaydedildi: {output_file}")
    
    def print_statistics(self):
        """İstatistikleri yazdır"""
        print("\n" + "="*80)
        print("📊 IP HARİTA İSTATİSTİKLERİ")
        print("="*80)
        
        total_ips = len(self.ip_locations)
        
        print(f"\n📌 Toplam Benzersiz IP: {total_ips:,}")
        print(f"📍 Haritada Gösterilen IP: {total_ips:,}")
        
        # Ülke bazında istatistik
        country_stats = defaultdict(lambda: {'count': 0, 'ips': 0})
        for ip, loc in self.ip_locations.items():
            country = loc.get('country', 'Unknown')
            country_stats[country]['count'] += loc['count']
            country_stats[country]['ips'] += 1
        
        print(f"\n🌍 Ülke Bazında Dağılım (Top 10):")
        sorted_countries = sorted(country_stats.items(), key=lambda x: x[1]['count'], reverse=True)[:10]
        for i, (country, stats) in enumerate(sorted_countries, 1):
            print(f"  {i:2d}. {country:25s} - {stats['ips']:4,} IP, {stats['count']:7,} aktivite")
        
        # En aktif 10 IP
        print(f"\n🔥 En Aktif IP'ler (Top 10):")
        sorted_ips = sorted(
            self.ip_locations.items(),
            key=lambda x: x[1]['count'],
            reverse=True
        )[:10]
        
        for i, (ip, loc) in enumerate(sorted_ips, 1):
            print(f"  {i:2d}. {ip:20s} - {loc['count']:6,} aktivite "
                  f"({loc['country']}, {loc['city']})")

def main():
    print("="*80)
    print("COWRIE HONEYPOT - IP HARİTA GÖRSELLEŞTİRMESİ")
    print("Saldırgan IP Adreslerinin Dünya Haritasında Gösterimi")
    print("="*80)
    
    # Analiz başlat
    visualizer = IPMapVisualizer()
    
    # Log'ları yükle
    visualizer.load_logs()
    
    # IP'leri analiz et
    visualizer.analyze_ips()
    
    # İstatistikleri göster
    visualizer.print_statistics()
    
    print("\n" + "="*80)
    print("🗺️  HARİTALAR OLUŞTURULUYOR...")
    print("="*80)
    
    # Haritaları oluştur
    visualizer.create_heatmap('ip_heatmap.html')
    visualizer.create_marker_map('ip_markers.html', top_n=100)
    visualizer.create_cluster_map('ip_clusters.html')
    
    print("\n" + "="*80)
    print("✅ TÜM HARİTALAR BAŞARIYLA OLUŞTURULDU!")
    print("="*80)
    print("\nOluşturulan Dosyalar:")
    print("  1. ip_heatmap.html   - Isı haritası (saldırı yoğunluğu)")
    print("  2. ip_markers.html   - İşaretçi haritası (Top 100 IP)")
    print("  3. ip_clusters.html  - Kümeleme haritası (Tüm IP'ler)")
    print("\n💡 Haritaları tarayıcınızda açarak görüntüleyebilirsiniz!")
    print("="*80)

if __name__ == '__main__':
    main()
