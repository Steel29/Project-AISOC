<#
.SYNOPSIS
Redacts common SOC-sensitive values from text before sharing with AI tools.

.DESCRIPTION
Sanitize-SocText replaces sensitive values with typed placeholders such as
[REDACTED_EMAIL_1]. Repeated values receive the same placeholder within a run so
the sanitized text remains useful for analysis.

By default, the script redacts public IOCs such as public IPs, domains, URLs,
and hashes. Use -KeepPublicIocs when those indicators are safe and necessary for
analysis.

.EXAMPLE
.\tools\Sanitize-SocText.ps1 -InputPath .\notes.txt -OutputPath .\notes.sanitized.txt

.EXAMPLE
Get-Content .\notes.txt -Raw | .\tools\Sanitize-SocText.ps1

.EXAMPLE
.\tools\Sanitize-SocText.ps1 -InputPath .\notes.txt -KeepPublicIocs
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$InputPath,

    [string]$OutputPath,

    [switch]$KeepPublicIocs,

    [Parameter(ValueFromPipeline = $true)]
    [AllowNull()]
    [string]$InputObject
)

begin {
    $chunks = New-Object System.Collections.Generic.List[string]
    $placeholderMaps = @{}
    $placeholderCounts = @{}

    function Get-Redaction {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Category,

            [Parameter(Mandatory = $true)]
            [string]$Value
        )

        if (-not $placeholderMaps.ContainsKey($Category)) {
            $placeholderMaps[$Category] = @{}
            $placeholderCounts[$Category] = 0
        }

        if (-not $placeholderMaps[$Category].ContainsKey($Value)) {
            $placeholderCounts[$Category]++
            $placeholderMaps[$Category][$Value] = "[REDACTED_${Category}_$($placeholderCounts[$Category])]"
        }

        return $placeholderMaps[$Category][$Value]
    }

    function Replace-Pattern {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Text,

            [Parameter(Mandatory = $true)]
            [string]$Category,

            [Parameter(Mandatory = $true)]
            [string]$Pattern
        )

        return [regex]::Replace(
            $Text,
            $Pattern,
            {
                param($Match)
                Get-Redaction -Category $Category -Value $Match.Value
            },
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
    }

    function Test-PrivateIPv4 {
        param([string]$Address)

        $parts = $Address.Split(".") | ForEach-Object { [int]$_ }
        return (
            $parts[0] -eq 10 -or
            ($parts[0] -eq 172 -and $parts[1] -ge 16 -and $parts[1] -le 31) -or
            ($parts[0] -eq 192 -and $parts[1] -eq 168) -or
            ($parts[0] -eq 127) -or
            ($parts[0] -eq 169 -and $parts[1] -eq 254) -or
            ($parts[0] -eq 100 -and $parts[1] -ge 64 -and $parts[1] -le 127)
        )
    }

    function Replace-IPv4 {
        param([string]$Text)

        $pattern = "(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])"

        return [regex]::Replace($Text, $pattern, {
            param($Match)
            if (Test-PrivateIPv4 -Address $Match.Value) {
                return Get-Redaction -Category "PRIVATE_IP" -Value $Match.Value
            }

            if ($KeepPublicIocs) {
                return $Match.Value
            }

            return Get-Redaction -Category "PUBLIC_IP" -Value $Match.Value
        })
    }

    function Sanitize-Text {
        param([string]$Text)

        if ([string]::IsNullOrEmpty($Text)) {
            return $Text
        }

        $sanitized = $Text

        $alwaysRedact = @(
            @{ Category = "AUTH_HEADER"; Pattern = "(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+\/=-]{8,}" },
            @{ Category = "SECRET"; Pattern = "(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)\b\s*[:=]\s*['""]?[^'""\s,;]{4,}" },
            @{ Category = "EMAIL"; Pattern = "\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b" },
            @{ Category = "WINDOWS_USER"; Pattern = "\b[A-Z0-9._-]+\\[A-Z0-9._$-]+\b" },
            @{ Category = "UPN_USER"; Pattern = "\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.(?:local|internal|corp|lan|intra)\b" },
            @{ Category = "PHONE"; Pattern = "(?<!\w)(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{4}(?!\w)" },
            @{ Category = "GUID"; Pattern = "\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b" },
            @{ Category = "MAC"; Pattern = "\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b" },
            @{ Category = "IPV6"; Pattern = "\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b" },
            @{ Category = "UNC_PATH"; Pattern = "\\\\[A-Z0-9._$-]+\\[^\s,;]+" },
            @{ Category = "WINDOWS_PATH"; Pattern = "\b[A-Z]:\\[^\s,;]+" },
            @{ Category = "LINUX_PATH"; Pattern = "(?<!\w)/(?:etc|home|root|var|opt|usr|tmp|srv|mnt)/[^\s,;]*" },
            @{ Category = "INTERNAL_HOST"; Pattern = "\b[A-Z0-9][A-Z0-9-]{1,62}\.(?:local|internal|corp|lan|intra)\b" }
        )

        foreach ($rule in $alwaysRedact) {
            $sanitized = Replace-Pattern -Text $sanitized -Category $rule.Category -Pattern $rule.Pattern
        }

        $sanitized = Replace-IPv4 -Text $sanitized

        if (-not $KeepPublicIocs) {
            $iocRedact = @(
                @{ Category = "URL"; Pattern = "\bhttps?://[^\s<>""']+" },
                @{ Category = "SHA256"; Pattern = "\b[A-F0-9]{64}\b" },
                @{ Category = "SHA1"; Pattern = "\b[A-F0-9]{40}\b" },
                @{ Category = "MD5"; Pattern = "\b[A-F0-9]{32}\b" },
                @{ Category = "DOMAIN"; Pattern = "\b(?!(?:REDACTED_)[A-Z0-9_]+\b)(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,}\b" }
            )

            foreach ($rule in $iocRedact) {
                $sanitized = Replace-Pattern -Text $sanitized -Category $rule.Category -Pattern $rule.Pattern
            }
        }

        return $sanitized
    }
}

process {
    if ($PSBoundParameters.ContainsKey("InputObject") -and $null -ne $InputObject) {
        $chunks.Add($InputObject)
    }
}

end {
    if ($InputPath) {
        if (-not (Test-Path -LiteralPath $InputPath)) {
            throw "InputPath not found: $InputPath"
        }

        $text = Get-Content -LiteralPath $InputPath -Raw
    } elseif ($chunks.Count -gt 0) {
        $text = $chunks -join [Environment]::NewLine
    } else {
        $text = [Console]::In.ReadToEnd()
    }

    $result = Sanitize-Text -Text $text

    if ($OutputPath) {
        Set-Content -LiteralPath $OutputPath -Value $result -Encoding UTF8
    } else {
        Write-Output $result
    }
}
