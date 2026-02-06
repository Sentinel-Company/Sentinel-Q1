# GNU target kurulumu - build.ps1 oncesi bir kez calistirin
# Bu komutu normal PowerShell/CMD'de calistirin (Cursor disinda)

Write-Host "Rust GNU target yukleniyor..." -ForegroundColor Cyan
rustup target add x86_64-pc-windows-gnu

if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] Kurulum tamam. Simdi: .\build.ps1" -ForegroundColor Green
} else {
    Write-Host "[HATA] Yukleme basarisiz. Internet baglantinizi kontrol edin." -ForegroundColor Red
}
