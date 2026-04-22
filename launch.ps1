param(
  [int]$Port = 3000
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

Write-Host ""
Write-Host "== Safe Audit Agents Launcher ==" -ForegroundColor Cyan

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  Write-Host "Node.js 未安装或不在 PATH 中，请先安装 Node.js 18+。" -ForegroundColor Red
  exit 1
}

$nodeVersion = (node -v).Trim()
Write-Host "Node.js: $nodeVersion"

$major = [int](($nodeVersion -replace '^v', '').Split('.')[0])
if ($major -lt 18) {
  Write-Host "需要 Node.js 18+，当前版本过低。" -ForegroundColor Red
  exit 1
}

$downloadsDir = Join-Path $root "workspace\downloads"
if (-not (Test-Path $downloadsDir)) {
  New-Item -ItemType Directory -Path $downloadsDir -Force | Out-Null
}

$provider = if ($env:LLM_PROVIDER) { $env:LLM_PROVIDER } else { "openai" }
Write-Host "LLM Provider: $provider"

if (-not $env:OPENAI_API_KEY -and -not $env:LLM_API_KEY -and -not $env:ANTHROPIC_API_KEY -and -not $env:GEMINI_API_KEY -and -not $env:DEEPSEEK_API_KEY -and -not $env:QWEN_API_KEY) {
  Write-Host "未检测到任何大模型 API Key，系统仍可启动，但 AI 扩展能力会显示为未配置。" -ForegroundColor Yellow
}

$env:PORT = "$Port"
Write-Host "Launching on http://localhost:$Port" -ForegroundColor Green
node server.js
