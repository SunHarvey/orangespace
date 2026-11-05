# Production ACL/reparse policy with injected OS metadata; Linux, not native ACL.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../Common.ps1')
function Reject($Body,$message) {
    try { & $Body } catch { if ($_.Exception.Message -like "*$message*") { return }; throw }
    throw "Expected rejection: $message"
}
$script:ancestor = [pscustomobject]@{FullName='ancestor';Parent=$null;Attributes=0;PSIsContainer=$true}
$script:leaf = [pscustomobject]@{FullName='leaf';Parent=$script:ancestor;Attributes=0;PSIsContainer=$true}
$script:foreignAt=''; $script:mask=0; $script:reparseAt=''
function Get-Item($LiteralPath) {
    $item = if ($LiteralPath -eq 'leaf') { $script:leaf } else { $script:ancestor }
    $item.Attributes = if ($LiteralPath -eq $script:reparseAt) { 1024 } else { 0 }
    return $item
}
function Get-Acl($LiteralPath) {
    $acl=[pscustomobject]@{AreAccessRulesProtected=$true; Foreign=($LiteralPath -eq $script:foreignAt)}
    $acl | Add-Member ScriptMethod GetOwner { param($type) return [pscustomobject]@{Value='S-1-5-18'} }
    $acl | Add-Member ScriptMethod GetAccessRules {
        param($explicit,$inherited,$type)
        $sid=if ($this.Foreign) { 'S-1-5-32-545' } else { 'S-1-5-18' }
        return [pscustomobject]@{AccessControlType='Allow';IdentityReference=[pscustomobject]@{Value=$sid};FileSystemRights=$script:mask;PropagationFlags=0}
    }
    return $acl
}
Assert-Protected leaf
foreach ($where in @('leaf','ancestor')) {
    $script:foreignAt=''
    $script:reparseAt=$where
    Reject { Assert-Protected leaf } 'Reparse'
    $script:reparseAt=''
    $script:foreignAt=$where
    foreach ($mask in @(0x40000000,0x10000000,0x00040000,0x00080000,0x00010000,0x40)) {
        $script:mask=$mask
        Reject { Assert-Protected leaf } $(if ($where -eq 'leaf') {'Unprivileged'} else {'Writable ancestor'})
    }
}
Write-Output 'PASS injected production ACL: root/ancestor reparse; generic and specific foreign mutation rights'
