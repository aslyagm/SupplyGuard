# SupplyGuard

Python bağımlılıkları için **kurulum öncesi** taklit paket (typosquatting) ve
yapay zekâ kaynaklı uydurma paket (slopsquatting) tespit aracı.

BIL 420/520 Siber Güvenliğe Giriş, Güz 2026, dönem projesi.

> SupplyGuard hiçbir paketi indirmez, kurmaz veya çalıştırmaz. Sadece paket
> isimlerine ve PyPI'ın herkese açık JSON API'sine bakar. Hiçbir isim PyPI'a kaydedilmez.

## Ne yapar?

1. `requirements.txt` dosyasını okur, isimleri PEP 503'e göre normalize eder.
2. Her ismi en popüler ~5000 PyPI paketiyle karşılaştırır (Damerau-Levenshtein).
3. Taklit **türünü** tespit eder: harf yer değişimi, klavyede komşu tuş,
   benzer karakter (`rn`→`m`, `l`→`i`), ayraç (`py-yaml` / `pyyaml`),
   ön/son ek (`python-`, `-py`), eksik/fazla harf.
4. PyPI bilgilerini (paketin yaşı, sürüm sayısı, proje linki, açıklama, var olup olmadığı)
   ekleyerek gerekçeli tek bir **risk puanı** üretir (OK / LOW / MEDIUM / HIGH).
5. `slopcheck`: Bir LLM'e görevler için paket önerisi sorar, önerilen
   paketlerin PyPI'da gerçekten var olup olmadığını kontrol eder.

### GuardDog'dan farkı

| | GuardDog | SupplyGuard |
|---|---|---|
| Ne zaman | Paket indirildikten sonra, kaynak kodu taranır | Kurulumdan önce, sadece isim + metadata |
| Typo tespiti | Benzerlik kuralı | Taklit türü sınıflandırması |
| Çıktı | Kural eşleşmeleri | Gerekçeli birleşik risk puanı |
| LLM halüsinasyonu | Yok | `slopcheck` |

## Kurulum

```bash
python -m venv .venv
.venv\Scripts\activate          # Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
```

Çalışmak için dış bağımlılık gerekmez (sadece standart kütüphane), testler için `pytest` gerekir.

## Kullanım

```bash
supplyguard scan examples/requirements-demo.txt            # PyPI bilgisiyle
supplyguard scan requirements.txt --offline --json out.json
supplyguard update-popular --limit 5000                    # popüler listeyi güncelle
```

HIGH seviyesinde bulgu olursa çıkış kodu 1 olur (CI'da kullanılabilir).

### Slopsquatting kontrolü

[Groq](https://console.groq.com) ücretsiz katmanından bir API anahtarı alın ve ortam değişkeni olarak tanımlayın
(anahtarı **asla** koda veya repoya koymayın):

```powershell
$env:GROQ_API_KEY = "..."
supplyguard slopcheck --tasks eval/tasks.txt --csv reports/slop.csv
```

Model `--model` ile veya `SUPPLYGUARD_MODEL` ortam değişkeniyle değiştirilebilir.

## Değerlendirme

```bash
python eval/fetch_openssf.py   # OpenSSF zararlı paket listesinden isimleri çıkarır (talimat dosyanın başında)
python eval/run_eval.py        # Levenshtein baseline ve SupplyGuard karşılaştırması
python eval/run_eval.py --online
```

- Pozitifler: `eval/malicious_names.txt` (OpenSSF `malicious-packages`, sadece isimler)
- Negatifler: `eval/benign_pairs.csv` (birbirine benzeyen meşru paketler)
- Metrikler: precision, recall, false positive rate

## Proje yapısı

```
supplyguard/
  parser.py       requirements.txt okuma, PEP 503 normalizasyonu
  similarity.py   Levenshtein (baseline) + Damerau-Levenshtein
  typo_types.py   taklit türü sınıflandırması
  popular.py      popüler paket listesi (data/top_packages.txt)
  pypi.py         PyPI JSON API, önbellekli
  scoring.py      risk puanı ve gerekçeler
  report.py       konsol / JSON / CSV
  slopsquat.py    LLM önerisi + PyPI varlık kontrolü
  cli.py
eval/             test seti ve değerlendirme betikleri
tests/            pytest
```

## Ders bağlantısı

Day 13 (güvenli SDLC), Day 14 (yazılım tedarik zinciri, typosquatting, dependency confusion),
Day 16 (tespit kalitesi metrikleri), MITRE ATT&CK T1195.
