param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("start", "stop", "status")]
    [string]$Action
)

Write-Host "Managing AI Firewall Services..."
python manage_services.py $Action

if ($Action -eq "start") {
    Write-Host "`nImportant: Services are now running and will consume AWS Free Tier resources."
    Write-Host "Remember to run 'manage_services.ps1 stop' when you're done testing to avoid exceeding free tier limits."
} elseif ($Action -eq "stop") {
    Write-Host "`nAll services have been stopped to preserve AWS Free Tier resources."
} 