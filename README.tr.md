<div align="center">

# 🛡️ Kalkan

**x86-64 için Rust ile yazılmış, yetki (capability) tabanlı, güvenlik odaklı bir mikroçekirdek.**

[English README](README.md) · [Mimari](docs/ARCHITECTURE.md) · [Tehdit modeli](docs/THREAT_MODEL.md) · [Sistem çağrıları](docs/SYSCALLS.md) · [Derleme](docs/BUILDING.md)

</div>

---

Kalkan tek bir fikir üzerine kurulu küçük bir mikroçekirdektir: **doğrulanabilen
hiçbir şeye güvenilmez.** Kullanıcı programlarının "varsayılan yetkisi" (ambient
authority) yoktur; her çekirdek nesnesine yalnızca sahte üretilemeyen bir
*capability* (yetki jetonu) ile erişilir ve bu jetonun hakları yalnızca
**azaltılabilir**. Çekirdek açılışta kendi donanım korumalarını doğrular, yüklediği
her programı doğrular ve her CI çalıştırmasında güvenilmeyen bir sürecin
sandbox'tan kaçmaya çalıştığı saldırgan bir test paketiyle gelir.

## Öne çıkanlar

- 🔑 **Capability modeli, varsayılan yetki yok** — seL4 tarzı yetki alanları
  (CSpace), monoton haklar, taklit edilemeyen "badge"ler, türetme ağacı ile tam
  geri alma (revoke), GRANT hakkına dayalı hapsetme (confinement).
- 🦀 **Yapısı gereği bellek güvenli** — Rust, yalnızca stable derleyici. `unsafe`
  kod dört alt seviye modül dışında **derleyici tarafından yasaklanmıştır**; her
  `unsafe` bloğunun bir `SAFETY:` gerekçesi vardır (Clippy ile zorunlu).
- 🧪 **Test edilebilir politika** — Tüm erişim kararları [`kcore`](kcore/src/lib.rs)
  içindedir: `#![forbid(unsafe_code)]`, sıfır bağımlılık, bilgisayarda birim ve
  özellik (property) testleri, CI'da fuzzing.
- 🧱 **Açılışta doğrulanan donanım sertleştirmesi** — NX, SMEP, SMAP (hiç
  kaldırılmaz), UMIP, CR0.WP, CR4.TSD, kullanıcıya kapalı SIMD, her yerde W^X,
  çalıştırılamaz fiziksel bellek haritası, koruma sayfaları, KASLR. Çekirdek her
  birini kendi kontrol yazmaçlarını ve sayfa tablolarını okuyarak **kontrol eder**;
  zorunlu bir koruma yoksa açılmayı reddeder (fail-closed).
- 🔗 **Doğrulanmış açılış zinciri** — Sürümü, commit'i ve BLAKE2b özeti
  sabitlenmiş önyükleyici. Önyükleyici çekirdeği ve modülleri doğrular; çekirdek
  modülleri içine gömülü özetlerle **bir kez daha** doğrular. Kurcalama CI'da test
  edilir.
- ⚔️ **Saldırgan test paketi** — Çekirdeğe aktif olarak saldıran bir süreç dahil 62
  açılış zamanı güvenlik testi ve önyükleme bölümü kurcalama testi.
- 📦 **Sıfır bağımlılık** — Çekirdekte ve politika çekirdeğinde üçüncü taraf crate
  yok.

## Hızlı başlangıç

Rust ([rustup](https://rustup.rs)), QEMU ve git gerekir. `rust-toolchain.toml`
içindeki sabit derleyici sürümü otomatik kurulur.

```powershell
winget install Rustlang.Rustup
winget install SoftwareFreedomConservancy.QEMU
rustup set default-host x86_64-pc-windows-gnu   # Visual Studio yoksa
```

```sh
cargo xtask run             # her şeyi derle ve Kalkan'ı QEMU'da aç
cargo xtask test            # güvenlik paketi + kurcalama testi (CI'ın çalıştırdığı)
cargo test -p kalkan-core   # politika çekirdeğinin birim/özellik testleri
```

Linux: `sudo apt install qemu-system-x86 ovmf` · macOS: `brew install qemu`.
Ayrıntılar: [docs/BUILDING.md](docs/BUILDING.md).

## Güvenlik modeli (özet)

| Tehdit | Önlem |
|---|---|
| Sahte referansla yetki yükseltme | Yetkiler çekirdek nesneleridir, slot numarasıyla adreslenir; kimlikler nesil sayaçlıdır |
| Hak yükseltme | Türetme yalnızca hak kaldırabilir (tüm kombinasyonlar test edilir) |
| Yetki sızdırma | Başka bir CSpace'e aktarım GRANT hakkı ister; revoke tüm alt yetkileri **ve eşlemelerini** siler |
| IPC'de kimlik taklidi | Badge bir kez atanır ve çekirdek tarafından iletilir |
| Sistem çağrısına çekirdek işaretçisi | Çekirdek kullanıcı işaretçilerini asla doğrudan okumaz; sayfa tablolarını yürüyüp doğrudan harita üzerinden kopyalar |
| ret2usr | SMEP + SMAP, hiç kaldırılmaz (çekirdekte `stac` yok) |
| Kod enjeksiyonu | Çekirdek imajı, fiziksel harita, heap, yığınlar ve kullanıcı programlarında W^X; W^X takma adlar (alias) üzerinden de çerçeve başına korunur |
| Bozuk/kötü niyetli çalıştırılabilir | Katı, panik üretmeyen, fuzz edilen ELF doğrulayıcı |
| Adres sızıntısı | KASLR, rastgele fiziksel harita, rastgele çekirdek yığın/heap/MMIO yerleşimi, kullanıcı ASLR, UMIP |
| Spectre v1/v2, MDS, SWAPGS | Dalsız indeks kısıtlama, IBPB, VERW, `swapgs` sonrası `lfence`, girişte tüm yazmaçların sıfırlanması |
| SYSRET açığı (CVE-2012-0217) | Çekirdek her zaman `iretq` ile döner |
| SIMD durum sızıntısı (LazyFP) | Kullanıcıya x87/SSE/AVX kapalı |
| Bellek yeniden kullanımıyla sızıntı | Çerçeveler ayırmada **ve** serbest bırakmada sıfırlanır |
| Heap bozulması | Kodlanmış serbest listeler, zehirleme, çift serbest bırakma tespiti, koruma sayfaları |
| Kaynak tüketme | Geri alınabilir untyped bellek bütçeleri, adres alanı başına sayfa tablosu kotası (boşalan tablolar geri alınır), kullanıcının dokunamadığı çekirdek bellek rezervi ve her çekirdek tablosunda sert sınırlar |
| Terminal enjeksiyonu | Kullanıcı konsol çıktısı temizlenir (ESC/kontrol karakteri yok) |
| Açılışta kurcalama | Sabitlenmiş önyükleyici; BLAKE2b doğrulaması hem önyükleyicide hem çekirdekte |

Henüz kapsanmayanlar (SMP, IOMMU, KPTI, ...) [tehdit modelinde](docs/THREAT_MODEL.md#known-limitations)
açıkça listelenmiştir.

## Uyarı

Kalkan eğitim ve araştırma amaçlı bir projedir. Biçimsel olarak doğrulanmamış ve
bağımsız bir denetimden geçmemiştir; gerçek verileri korumak için kullanılmamalıdır.
Güvenlik açıklarını [SECURITY.md](SECURITY.md) içinde anlatıldığı şekilde bildirin.

## Lisans

[MIT](LICENSE-MIT) veya [Apache-2.0](LICENSE-APACHE), tercihinize göre.
