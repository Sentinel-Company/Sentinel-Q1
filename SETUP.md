# Kurulum Rehberi - Hybrid Titan

## Extract Penceresi Kapandıysa

Eğer bir "Extract" veya kurulum penceresi açıldı ve siz kapattıysanız:

### 1. Rust Kurulumu Kontrolü

PowerShell'de çalıştırın:

```powershell
cargo --version
```

**Çıktı:** `cargo 1.x.x` → Kurulum tamam  
**Hata:** `cargo tanınmıyor` → Kurulum eksik

### 2. Rust Kurulumu (Eksikse)

1. https://rustup.rs adresine gidin
2. **rustup-init.exe** indirin
3. Çalıştırın ve talimatları takip edin
4. **Önemli:** Kurulum bitene kadar Extract/Setup penceresini kapatmayın
5. Kurulum sonunda **yeni bir terminal** açın (PATH güncellenir)

### 3. PATH Kontrolü

Rust kurulu ama `cargo` çalışmıyorsa:

```powershell
$env:Path += ";$env:USERPROFILE\.cargo\bin"
cargo --version
```

Kalıcı olması için: Sistem → Gelişmiş → Ortam Değişkenleri → Path'e ekleyin:
```
%USERPROFILE%\.cargo\bin
```

### 4. Tam Kurulum Sonrası

```powershell
cd "c:\Users\User\Documents\AHMET ERNE\Sesli-ai\NOVA-v2"
.\build.ps1 -CheckOnly   # Bağımlılık kontrolü
.\build.ps1              # Derleme
```
