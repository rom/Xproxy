// Rules for the streaming scanner. This is a subset of the YARA
// language implemented in Go — see docs/CONFIG.md for exactly what is
// supported. Anything outside it is refused at load with the line
// number, rather than quietly matching nothing.
//
// Two differences from scanning a file are worth keeping in mind while
// writing rules here:
//
//   * A rule fires the first time its condition becomes true, not at
//     the end of the stream. Write conditions that can be satisfied by
//     a prefix; one that needs the whole object is one that decides
//     after the transfer.
//   * filesize means the bytes seen so far. "filesize > 1MB" becomes
//     true partway through a large transfer; "filesize < 100" is only
//     reliable near the start.

rule executable_header : malware
{
    meta:
        description = "A PE or ELF header in a stream that should carry neither"
        severity    = "high"
    strings:
        $mz  = { 4D 5A }          // "MZ"
        $pe  = { 50 45 00 00 }    // "PE\0\0"
        $elf = { 7F 45 4C 46 }    // "\x7fELF"
    condition:
        ($mz and $pe) or $elf
}

rule archive_of_executables : malware
{
    meta:
        description = "A zip whose first entry names an executable"
    strings:
        $zip = { 50 4B 03 04 }
        $exe = ".exe" nocase
        $scr = ".scr" nocase
        $js  = ".js" nocase
    condition:
        $zip and any of ($exe, $scr, $js)
}

rule shell_payload : exploit
{
    meta:
        description = "Shapes that appear in a dropped shell script and nowhere useful"
    strings:
        $a = "curl -s" nocase
        $b = "| sh" nocase
        $c = "wget -q" nocase
        $d = "chmod +x" nocase
        $e = "/dev/tcp/"
    condition:
        3 of them
}

rule credential_exfiltration : exfiltration
{
    meta:
        description = "Secrets leaving in a stream"
    strings:
        $aws   = /AKIA[0-9A-Z]{16}/
        $pem   = "-----BEGIN PRIVATE KEY-----"
        $rsa   = "-----BEGIN RSA PRIVATE KEY-----"
        $ssh   = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $token = /gh[pousr]_[A-Za-z0-9]{36}/
    condition:
        any of them
}

rule internal_marker : exfiltration
{
    meta:
        description = "A marker planted in documents that must not leave the estate"
        note        = "A honeytoken for files: it exists to be matched"
    strings:
        $a = "XPROXY-INTERNAL-ONLY" wide ascii
    condition:
        $a
}

rule webshell_upload : malware
{
    meta:
        description = "The opening of a PHP webshell"
    strings:
        $php  = "<?php"
        $eval = "eval(" nocase
        $sys  = "system(" nocase
        $pass = "passthru(" nocase
        $b64  = "base64_decode(" nocase
    condition:
        $php and 2 of ($eval, $sys, $pass, $b64)
}

rule sqlite_database : data
{
    meta:
        description = "A database file, which is rarely what a form upload is"
    strings:
        $hdr = "SQLite format 3\x00"
    condition:
        $hdr
}
