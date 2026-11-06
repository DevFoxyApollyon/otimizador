# Compila o PCDiagnostico.exe usando o compilador C# que já vem com o .NET Framework 4.8 do Windows.
# Não precisa instalar Visual Studio, .NET SDK nem nada extra.
$ErrorActionPreference = 'Stop'
$raiz = $PSScriptRoot
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { throw "csc.exe não encontrado em $csc. Ative o .NET Framework 4.8 em 'Recursos do Windows'." }

$dist = Join-Path $raiz 'dist'
New-Item -ItemType Directory -Force $dist | Out-Null
$saida = Join-Path $dist 'PCDiagnostico.exe'
$fontes = Get-ChildItem (Join-Path $raiz 'src') -Filter *.cs | ForEach-Object { $_.FullName }

& $csc /nologo /target:exe /platform:anycpu /optimize+ /codepage:65001 `
    "/out:$saida" "/win32manifest:$(Join-Path $raiz 'app.manifest')" `
    /reference:System.Management.dll /reference:System.Core.dll /reference:Microsoft.CSharp.dll `
    /reference:System.ServiceProcess.dll /reference:System.DirectoryServices.AccountManagement.dll /reference:System.Web.Extensions.dll /reference:System.Xml.Linq.dll /reference:Microsoft.VisualBasic.dll `
    $fontes
if ($LASTEXITCODE -ne 0) { throw "Falha na compilação (código $LASTEXITCODE)." }
Write-Host "OK: $saida ($([math]::Round((Get-Item $saida).Length / 1KB)) KB)"
