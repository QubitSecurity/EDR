rule ELF_BPFDoor
{
meta:
description = "BPFDoor Malware(ELF) Detection rule"
author = "KrCERT/CC Threat Hunting Analysis Team"
date = "2025-05-06"
hash = "c7f693f7f85b01a8c0e561bd369845f40bff423b0743c7aa0f4c323d9133b5d4"
hash = "3f6f108db37d18519f47c5e4182e5e33cc795564f286ae770aa03372133d15c4"
hash = "95fd8a70c4b18a9a669fec6eb82dac0ba6a9236ac42a5ecde270330b66f51595"
hash = "aa779e83ff5271d3f2d270eaed16751a109eb722fca61465d86317e03bbf49e4"
ver = "1.1"

strings:
$pty_1 = "/dev/ptm"
$pty_2 = "ptem"
$pty_3 = "ldterm"
$pty_4 = "ttcompat"

// for ( i = 0xA597; i <= 0xA97E; ++i )
$bind_port_1 = {C7 45 ?? 97 A5 00 00 EB}
$bind_port_2_1 = {83 45 ?? 01 81 7D ?? 7E A9 00 00 7E}
$bind_port_2_2 = {81 7D ?? 7E A9 00 00 7E}

// v1.1 : added new pattern "PS1=[\\u@\\h : "
$ps1 = {C6 85 ?? ?? FF FF 50 C6 85 ?? ?? FF FF 53 C6 85 ?? ?? FF FF 31 C6 85 ?? ?? FF FF 3D C6 85 ?? ?? FF FF 5B C6 85 ?? ?? FF FF 5C C6 85 ?? ?? FF FF 75 C6 85 ?? ?? FF FF 40 C6 85 ?? ?? FF FF 5C C6 85 ?? ?? FF FF 68}

// v1.1 : bpf filter modify (dbus, hald, trend-B, Trend-E)
$bpf_filter_1 = {B1 00 00 00 0E 00 00 00 48 00 00 00 16 00 00 00 15 00 ?? ?? ?? ?? 00 00 15 00 00 07 01 00 00 00 28 00 00 00 14 00 00 00 45 00 (11|1A) 00 FF 1F 00 00}
$bpf_filter_2 = {07 00 00 00 00 00 00 00 (40|48) 00 00 00 00 00 00 00 02 00 00 00 (00|01|03) 01 00 00 00 00 00 00 00 ?? ?? ?? ?? 02 00 00 00 (01|02|04) 00 00 00 61 00 00 00 (01|02|04) 00 00 00}
$bpf_filter_3 = {07 00 00 00 00 00 00 00 40 00 00 00 0E 00 00 00 15 00 00 01 39 39 39 39 06 00 00 00 FF FF 00 00 06 00 00 00 00 00 00 00}
$bpf_filter_4 = {48 00 00 00 10 00 00 00 15 00 01 00 BB 01 00 00 15 00 00 01 16 00 00 00 06 00 00 00 00 00 04 00 06 00 00 00 00 00 00 00}

// I5*AYbs@LdaWbsO
$md5_salt = {C6 45 ?? 49 C6 45 ?? 35 C6 45 ?? 2A C6 45 ?? 41 C6 45 ?? 59 C6 45 ?? 62 C6 45 ?? 73 C6 45 ?? 40 C6 45 ?? 4C C6 45 ?? 64 C6 45 ?? 61 C6 45 ?? 57 C6 45 ?? 62 C6 45 ?? 73 C6 45 ?? 4F}

// qmgr -l -t fifo
$pname = {C6 ?? ?? ?? FF FF 71 C6 ?? ?? ?? FF FF 6D C6 ?? ?? ?? FF FF 67 C6 ?? ?? ?? FF FF 72 C6 ?? ?? ?? FF FF 20 C6 ?? ?? ?? FF FF 2D C6 ?? ?? ?? FF FF 6C C6 ?? ?? ?? FF FF 20 C6 ?? ?? ?? FF FF 2D C6 ?? ?? ?? FF FF 74 C6 ?? ?? ?? FF FF 20 C6 ?? ?? ?? FF FF 66 C6 ?? ?? ?? FF FF 69 C6 ?? ?? ?? FF FF 66 C6 ?? ?? ?? FF FF 6F}

$solaris_1 = "(udp[8:2]=0x7255) or (icmp[8:2]=0x7255)"
$solaris_2 = "HISTFILE=/dev/null"
$solaris_3 = "MYSQL_HISTFILE=/dev/null"

condition:
uint32(0) == 0x464C457F and
(
(all of ($pty*) and (2 of ($bind_port*) or $ps1)) or // v1.1
((all of ($pty*) or $ps1) and 2 of ($bind_port*)) or // v1.1
(1 of ($bpf_filter*)) or
($md5_salt or $pname) or
(all of ($solaris*))
)
}

rule ELF_BPFDoor_Controller
{
meta:
description = "BPFDoor Malware(ELF) Controller Detection rule"
author = "KrCERT/CC Threat Hunting Analysis Team"
date = "2025-05-06"
hash = "93f4262fce8c6b4f8e239c35a0679fbbbb722141b95a5f2af53a2bcafe4edd1c"
hash = "1925e3cd8a1b0bba0d297830636cdb9ebf002698c8fa71e0063581204f4e8345"
hash = "591198c234416c6ccbcea6967963ca2ca0f17050be7eed1602198308d9127c78"
ver = "1.1"

strings:
// v1.1 : added new pattern
$pname = /\/usr\/sbin\/[a-z]{2,8}/
$str_1 = "[-] option requires an argument -- d"
$str_2 = ":h:d:l:s:b:t:"

// mov cs:magic_flag, 5571h
$magic = {C7 05 ?? ?? ?? 00 71 55 00 00}

$env_1 = "export TERM=vt100"
$env_2 = "export MYSQL_HISTFILE=/dev/null"
$env_3 = "export HISTFILE=/dev/null"
$env_4 = "unset PROMPT_COMMAND"
$env_5 = "export HISTSIZE=100"

condition:
uint32(0) == 0x464C457F and
($pname or 1 of ($str*)) and $magic and (all of ($env*))
}
