<div align="center">

# Mythos
**Session-Scoped Client Verification & Forensic Telemetry Utility**

[**mythos.ac**](https://mythos.ac)

</div>

---

## Overview

Mythos is an on-demand, portable client verification utility used by community servers (primarily within the FiveM / Cfx.re ecosystem) that a player runs once with their own consent prior to gameplay or an interview.

It **does not** install a background service, system startup entry, or kernel-mode driver. Mythos runs strictly for the duration of a single-use, 8-character PIN session, inspects operating system execution telemetry and platform integrity state, transmits an encrypted report to the verification server, and exits immediately.

This repository documents **what data Mythos collects**, **how that data is read at the code level**, **what is strictly out of scope**, and **how our 30-day automatic data retention policy works**.

> **Why isn't the entire scanner open-source?**  
> While our data collection boundaries and privacy practices are fully transparent, the detection heuristics, memory inspection logic, and anti-tamper layers remain proprietary so cheat developers cannot reverse-engineer bypasses against them.

---

## Execution Model

1. **Single-Run Lifecycle:** Each downloaded binary is bound to a single-use session PIN. Once the scan finishes, the process terminates completely.
2. **Zero Persistence:** No services, drivers, scheduled tasks, or registry autorun entries are created.
3. **Read-Only Inspection:** Mythos never modifies system files, game binaries, or registry configurations.

---

## What We Collect & How It Works

Below are the core telemetry categories collected during a scan, accompanied by the actual C++ implementation used by the client.

### 1. Discord Account Identifier (Public User ID & Username Only)

To link a scan session to the participant being verified, Mythos reads the **public Discord user ID (Snowflake) and username** of the locally logged-in Discord client.

Mythos **never** accesses Discord's encrypted token database (`Local Storage\leveldb`), direct messages, email address, or authentication credentials. Instead, it reads the `"user"` object from Discord's local Sentry crash-reporting scope file (`%APPDATA%\discord\sentry\scope_v3.json`). You can open this file in any text editor on your own machine to verify that it only stores your public `id` and `username`.

```cpp
// Source: platform/game/dcaccount.cpp
void ScanSentryScope(const fs::path& appDataDir, const std::string& accountType, std::vector<DiscordAccount>& outAccounts)
{
    const fs::path sentryDir = appDataDir / L"sentry";
    std::error_code ec;
    if (!fs::is_directory(sentryDir, ec))
    {
        return;
    }

    const std::wstring scopeFiles[] = { L"scope_v3.json", L"scope_v2.json", L"scope.json" };

    for (const std::wstring& fileName : scopeFiles)
    {
        const fs::path filePath = sentryDir / fileName;
        if (!fs::is_regular_file(filePath, ec))
        {
            continue;
        }

        const std::string content = ReadFileSharedLimited(filePath);
        if (content.empty())
        {
            continue;
        }

        // Only the "user": { "id": "...", "username": "..." } block is parsed.
        const std::string userMarker = "\"user\":{";
        const std::size_t userPos = content.find(userMarker);
        if (userPos != std::string::npos)
        {
            const std::string obj = ExtractEnclosingJsonObject(content, userPos + userMarker.size(), 512);
            const std::string id = FindJsonValue(obj, "id");
            const std::string username = FindJsonValue(obj, "username");

            if (IsDiscordId(id) || !username.empty())
            {
                DiscordAccount account{};
                account.accountType = accountType; // Normal, PTB, Canary, Vesktop
                if (IsDiscordId(id))
                {
                    account.userId = id;
                }
                account.username = username;
                account.discriminator = "0";
                MergeOrAddAccount(outAccounts, std::move(account));
            }
        }
    }
}
```

---

### 2. Application Execution History (BAM / DAM, Prefetch, AppCompatCache)

To verify whether external tools were executed before or during a game session and subsequently closed, Mythos reads standard Windows execution artifacts:

- **BAM / DAM (`Background Activity Moderator`):** Executable paths and last execution timestamps (`FILETIME`) stored under `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>`.
- **Windows Prefetch (`C:\Windows\Prefetch\*.pf`):** Executed binary names, run counts, and loaded module paths.
- **ShimCache / Amcache / PCA:** Windows Application Compatibility metadata (file size, SHA-1/SHA-256 digest, Authenticode signature status).

Because BAM stores paths in NT device format (`\Device\HarddiskVolume3\...`), Mythos resolves them to standard DOS drive letters (`C:\...`) via `QueryDosDeviceW`:

```cpp
// Source: platform/forensics/executions.cpp
std::map<std::wstring, std::wstring> BuildDeviceMap()
{
    std::map<std::wstring, std::wstring> devices;
    for (wchar_t letter = L'A'; letter <= L'Z'; ++letter)
    {
        const wchar_t drive[3] = { letter, L':', L'\0' };
        wchar_t target[MAX_PATH]{};
        if (QueryDosDeviceW(drive, target, static_cast<DWORD>(std::size(target))) > 0)
        {
            devices[ToLower(target)] = drive;
        }
    }
    return devices;
}

void ReadBamKey(
    const std::wstring& basePath,
    const std::map<std::wstring, std::wstring>& devices,
    const char* source,
    std::vector<ExecutionTrace>& traces)
{
    const RegistryKey root(HKEY_LOCAL_MACHINE, basePath);
    for (const std::wstring& sid : root.SubKeyNames())
    {
        const RegistryKey user(HKEY_LOCAL_MACHINE, basePath + L"\\" + sid);
        for (const std::wstring& name : user.ValueNames())
        {
            const auto data = user.ReadBinary(name);
            if (!data || data->size() < sizeof(std::uint64_t) || name.find(L'\\') == std::wstring::npos)
            {
                continue;
            }

            std::uint64_t fileTime = 0;
            std::memcpy(&fileTime, data->data(), sizeof(std::uint64_t));
            if (fileTime == 0)
            {
                continue;
            }

            traces.push_back({ ToDosPath(name, devices), FromFileTime(fileTime), source });
        }
    }
}
```

---

### 3. FiveM Session Logs & Game Directory Integrity

To correlate execution timestamps with active gameplay sessions and inspect loaded client modifications (`mods/`, `plugins/`, `citizen/`), Mythos parses `citizenfx_log_*.log` under `%LOCALAPPDATA%\FiveM\FiveM.app\logs`:

```cpp
// Extracts only session start/end timestamps, server join codes
// (cfx.re/join/ or fivem://connect/), and the in-game player nickname.
constexpr std::string_view kConnectMarker  = "fivem://connect/";
constexpr std::string_view kJoinMarker     = "cfx.re/join/";
constexpr std::string_view kNicknameMarker = "Loaded nickname: ";

std::string ExtractServerToken(const std::string& logContent)
{
    if (std::string joinCode = TokenAfter(logContent, kJoinMarker); !joinCode.empty())
    {
        return joinCode;
    }
    return TokenAfter(logContent, kConnectMarker);
}
```

---

### 4. Summary: In-Scope vs. Out-of-Scope Data

| Category | Collected (In Scope) | Never Collected (Out of Scope) |
| :--- | :--- | :--- |
| **Discord** | Public `user.id` and `user.username` (`sentry/scope_v3.json`) | Auth tokens (`leveldb`), passwords, emails, DMs, voice/chat logs |
| **Execution Artifacts** | BAM/DAM, Prefetch, PCA, ShimCache, USN journal metadata | Personal documents (`.docx`, `.pdf`, photos, videos), arbitrary file contents |
| **Web Browsers** | `Zone.Identifier` ADS metadata on downloaded executables | Saved passwords, cookies, session tokens, autofill or payment data |
| **System & Platform** | OS build, Secure Boot / TPM / HVCI state, loaded drivers (`WinVerifyTrust` signatures) | Keystrokes (keylogging), microphone audio, continuous screen recording |
| **Point-in-Time Capture** | Single desktop frame captured once at scan start, encrypted via `ECDH-P256 + AES-256-GCM` | Any capture outside the active scan execution |

---

## Data Security & 30-Day Automatic Deletion Policy

1. **Transport & Cryptographic Integrity:** All traffic between the scanner and the verification backend is encrypted over TLS 1.3 with ephemeral session keys (`ECDH-P256` / `AES-256-GCM`). Every completed report is bound to an `ECDSA-P256` signed server receipt.
2. **30-Day Retention Limit:** Verification reports, session screenshots, and associated diagnostic telemetry are retained for a maximum of **30 days (1 month)** from the scan timestamp. Once the 30-day window expires, records are **automatically and permanently purged** from our database and storage volumes.
3. **No Third-Party Sharing:** Collected data is never sold, rented, or shared with advertisers or data brokers. Reports are accessible solely to the authorized server administrators who issued the session PIN.

---

## Contact & Early Deletion Requests

For privacy inquiries, security disclosures, or requests to delete a scan report prior to the 30-day automatic purge window:

- **Website:** [https://mythos.ac](https://mythos.ac)
- **Privacy Policy:** [https://mythos.ac/en/privacy](https://mythos.ac/en/privacy)
- **Terms of Service:** [https://mythos.ac/en/terms](https://mythos.ac/en/terms)
