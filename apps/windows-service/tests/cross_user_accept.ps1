param([Parameter(Mandatory=$true)][string]$Result,[switch]$FoundationOnly)
$ErrorActionPreference='Stop'
$r=Get-Content -Raw -LiteralPath $Result | ConvertFrom-Json
if (-not $r.ok) { throw "cross-user acceptance failed: $($r.stage), native error $($r.error)" }
foreach($k in @('sid_different','logon_different','same_session','b_not_admin','profile_loaded','a_roundtrip','b_roundtrip','b_cannot_decrypt_a','b_acl_denied','profile_removed','account_removed','child_exited')) { if($r.$k -ne $true) { throw "missing acceptance: $k" } }
if(-not $FoundationOnly) { foreach($k in @('task_removed','processes_removed','root_removed','services_unchanged')) { if($r.$k -ne $true) { throw "outer acceptance failed: $k" } } }
if($FoundationOnly) { '{"foundation_acceptance":true,"full_acceptance":false}' } else { '{"full_acceptance":true}' }
