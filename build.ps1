param(
    [string]$SevenZipDir
)

$ErrorActionPreference = 'Stop'
$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not $SevenZipDir) {
    $command = Get-Command 7z.exe -ErrorAction SilentlyContinue
    if ($command) {
        $SevenZipDir = Split-Path -Parent $command.Source
    } else {
        foreach ($candidate in @(
            "$env:ProgramFiles\7-Zip",
            "${env:ProgramFiles(x86)}\7-Zip"
        )) {
            if (Test-Path -LiteralPath (Join-Path $candidate '7z.exe')) {
                $SevenZipDir = $candidate
                break
            }
        }
    }
}

if (-not $SevenZipDir) {
    throw '未找到 7-Zip。请用 -SevenZipDir 指定包含 7z.exe 和 7z.dll 的目录。'
}

$sevenzip = Join-Path $SevenZipDir '7z.exe'
$library = Join-Path $SevenZipDir '7z.dll'
$license = Join-Path $SevenZipDir 'License.txt'
$icon = Join-Path $projectDir 'ico.ico'
foreach ($path in @($sevenzip, $library, $license)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "缺少 7-Zip 文件：$path"
    }
}
if (-not (Test-Path -LiteralPath $icon -PathType Leaf)) {
    throw "缺少程序图标：$icon"
}

$pyinstaller = Get-Command pyinstaller.exe -ErrorAction SilentlyContinue
if (-not $pyinstaller) {
    throw '未找到 PyInstaller。请先安装：python -m pip install pyinstaller'
}

Push-Location $projectDir
try {
    & $pyinstaller.Source --noconfirm --onefile --windowed `
        --name PasswordRecoveryTool `
        --icon $icon `
        --distpath (Join-Path $projectDir 'dist') `
        --workpath (Join-Path $projectDir 'build') `
        --specpath (Join-Path $projectDir 'build') `
        --add-binary "${sevenzip};." `
        --add-binary "${library};." `
        --add-data "${license};." `
        (Join-Path $projectDir 'password-recovery-tool.py')
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller 打包失败，退出码：$LASTEXITCODE"
    }
    Write-Output (Join-Path $projectDir 'dist\PasswordRecoveryTool.exe')
} finally {
    Pop-Location
}
