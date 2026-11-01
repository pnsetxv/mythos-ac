<div align="center">

# Mythos
**Oturum Bazlı İstemci Doğrulama ve Adli Telemetri Aracı**

[**mythos.ac**](https://mythos.ac)

</div>

---

## Genel Bakış

Mythos, topluluk sunucularında (başta FiveM/Cfx.re ekosistemi olmak üzere) oyun veya mülakat öncesinde oyuncunun kendi onayıyla tek seferlik çalıştırdığı, kurulum gerektirmeyen (portable) bir doğrulama aracıdır.

Arka planda çalışan kalıcı bir servis veya çekirdek sürücüsü (kernel driver) **kurmaz**. Yalnızca tek kullanımlık 8 haneli bir PIN oturumu süresince çalışır, işletim sisteminin mevcut çalışma geçmişi ve bütünlük kayıtlarını okur, raporu şifreli olarak doğrulama sunucusuna iletir ve kapanır.

Bu depo, Mythos'un tarama sırasında **hangi verileri hangi yöntemlerle topladığını**, **nelere kesinlikle dokunmadığını** ve **veri saklama/silme politikasını** kaynak kod düzeyinde açıklamak amacıyla yayınlanmıştır.

> **Neden tüm kaynak kodu açık değil?**  
> Veri toplama sınırları ve gizlilik ilkeleri tamamen şeffaftır; ancak hile tespiti yapan bellek analizi, imza kuralları ve bütünlük doğrulama mekanizmaları hile geliştiricileri tarafından atlatılmaması (bypass edilmemesi) için kapalı kaynak tutulmaktadır.

---

## Çalışma Modeli

1. **Tek Seferlik Çalıştırma:** İndirilen `.exe` dosyası yalnızca ilgili PIN oturumu için geçerlidir. Tarama bittiğinde süreç tamamen sonlanır.
2. **Sıfır Kalıcılık:** Sistem başlangıcına (Autorun), Görev Zamanlayıcı'ya (Task Scheduler) veya Windows servislerine herhangi bir kayıt eklenmez.
3. **Salt-Okunur (Read-Only) İnceleme:** Sistem dosyaları, oyun dosyaları veya kayıt defteri girdileri değiştirilmez.

---

## Toplanan Veriler ve Teknik Uygulama

Mythos yalnızca doğrulama raporu için gereken sistem ve oyun telemetrisini okur. Aşağıda temel veri kalemlerinin nasıl toplandığı gerçek C++ kod kesitleriyle gösterilmiştir.

### 1. Discord Hesap Kimliği (Yalnızca Açık Kullanıcı ID ve Kullanıcı Adı)

Mythos, taramaya giren kişinin sunucu yöneticisiyle eşleştirilebilmesi için bilgisayarda oturum açılmış Discord hesabının **yalnızca açık kullanıcı kimliğini (Snowflake ID) ve kullanıcı adını** okur.

Discord'un şifreli token veritabanına (`Local Storage\leveldb`), özel mesajlarına veya e-posta adresine **erişilmez**. Bunun yerine Discord istemcisinin çökme raporlaması için düz metin olarak tuttuğu `%APPDATA%\discord\sentry\scope_v3.json` dosyasındaki `"user"` nesnesi okunur. (Kendi bilgisayarınızda bu dosyayı Not Defteri ile açarak içinde yalnızca `id` ve `username` bulunduğunu doğrulayabilirsiniz.)

```cpp
// Kaynak: platform/game/dcaccount.cpp
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

        // Yalnızca "user": { "id": "...", "username": "..." } bloğu ayrıştırılır.
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

### 2. Uygulama Çalıştırma Geçmişi (BAM / DAM, Prefetch, AppCompatCache)

Oyun oturumu sırasında veya hemen öncesinde çalıştırılıp kapatılmış yazılımları doğrulamak için Windows'un yerleşik çalışma geçmişi tabloları okunur:

- **BAM / DAM (`Background Activity Moderator`):** `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>` altındaki çalıştırılabilir dosya yolları ve son çalışma zaman damgaları (`FILETIME`).
- **Windows Prefetch (`C:\Windows\Prefetch\*.pf`):** Çalıştırılan uygulamaların adı, çalışma sayısı ve yüklediği modül yolları.
- **ShimCache / Amcache / PCA:** Windows Uygulama Uyumluluğu önbelleğinde tutulan dosya üstverileri (SHA-1/SHA-256 özeti, dosya boyutu, dijital imza durumu).

BAM kayıtları işletim sistemi tarafından NT aygıt yolu formatında (`\Device\HarddiskVolume3\...`) tutulduğu için `QueryDosDeviceW` ile sürücü harfine (`C:\...`) dönüştürülür:

```cpp
// Kaynak: platform/forensics/executions.cpp
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

### 3. FiveM Oturum Günlükleri ve Oyun İçi Eklenti Denetimi

Oyun sürecinin ne zaman başladığını, hangi sunucuya bağlandığını ve oyun dizinine (`mods/`, `plugins/`, `citizen/`) hangi arşivlerin yüklendiğini doğrulamak için `%LOCALAPPDATA%\FiveM\FiveM.app\logs` altındaki `citizenfx_log_*.log` dosyaları okunur:

```cpp
// citizenfx_log_*.log içinden yalnızca oturum zaman damgası, sunucu bağlantı kodu
// (cfx.re/join/ veya fivem://connect/) ve oyun içi kullanıcı adı ayrıştırılır.
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

### 4. Özet Tablo: Ne Toplanır, Ne Toplanmaz?

| Kategori | Toplanan Veri | Toplanmayan / Dokunulmayan Veri |
| :--- | :--- | :--- |
| **Discord** | Açık `user.id` ve `user.username` (`sentry/scope_v3.json`) | Token (`leveldb`), şifre, e-posta, özel mesajlar, ses/sohbet geçmişi |
| **Çalışma Geçmişi** | BAM/DAM, Prefetch, PCA, ShimCache, USN üstverileri | Kişisel belgeler (`.docx`, `.pdf`, fotoğraflar, videolar), dosya içerikleri |
| **Tarayıcılar** | İndirilen çalıştırılabilir dosyaların (`Zone.Identifier`) kaynak durumu | Tarayıcı şifreleri, çerezler (cookies), oturum anahtarları, kredi kartları |
| **Sistem ve Donanım** | İşletim sistemi sürümü, Secure Boot / TPM / HVCI durumu, yüklü sürücüler (`WinVerifyTrust` imzaları) | Klavye tuş vuruşları (keylogger), mikrofon kaydı, sürekli ekran kaydı |
| **Anlık Ekran Görüntüsü** | Yalnızca tarama başlangıcında 1 kez alınan ve `ECDH-P256 + AES-256-GCM` ile uçtan uca şifrelenen masaüstü görüntüsü | Tarama dışında veya arka planda görüntü alma |

---

## Veri Güvenliği ve 1 Aylık (30 Gün) Silme Politikası

1. **Aktarım Güvenliği:** İstemci ile sunucu arasındaki tüm iletişim TLS 1.3 ve oturuma özel kriptografik anahtarlarla (`ECDH-P256` / `AES-256-GCM`) şifrelenir. Her rapor, değiştirilemezliğini garanti eden `ECDSA-P256` sunucu makbuzu ile mühürlenir.
2. **Saklama Süresi (30 Gün):** Oluşturulan doğrulama raporları, ekran görüntüleri ve ilişkili tüm teknik telemetri verileri oluşturulma tarihinden itibaren **en fazla 1 ay (30 gün)** boyunca saklanır. 30 günü dolduran oturum kayıtları sunucu veritabanından ve depolama alanından **otomatik olarak kalıcı biçimde silinir**.
3. **Üçüncü Taraflarla Paylaşmama:** Toplanan veriler reklam ağları, veri simsarları veya üçüncü taraf şirketlerle kesinlikle paylaşılmaz ve satılmaz; yalnızca PIN kodunu oluşturan yetkili sunucu inceleme ekibi tarafından ilgili oturum kapsamında görüntülenebilir.

---

## İletişim ve Veri Silme Talepleri

Veri işleme süreçleri, güvenlik bildirimleri veya 30 günlük süre dolmadan rapor silme talepleriniz için resmi web sitemiz üzerinden bizimle iletişime geçebilirsiniz:

- **Web:** [https://mythos.ac](https://mythos.ac)
- **Gizlilik Politikası:** [https://mythos.ac/gizlilik](https://mythos.ac/gizlilik)
- **Kullanım Koşulları:** [https://mythos.ac/kosullar](https://mythos.ac/kosullar)
