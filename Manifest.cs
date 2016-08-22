using Newtonsoft.Json;
using SteamAuth;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

public class Manifest
{
    private const int PBKDF2_ITERATIONS = 50000; //Set to 50k to make program not unbearably slow. May increase in future.
    private const int SALT_LENGTH = 8;
    private const int KEY_SIZE_BYTES = 32;
    private const int IV_LENGTH = 16;

    [JsonProperty("encrypted")]
    public bool Encrypted { get; set; }

    [JsonProperty("first_run")]
    public bool FirstRun { get; set; } = true;

    [JsonProperty("entries")]
    public List<ManifestEntry> Entries { get; set; }

    [JsonProperty("periodic_checking")]
    public bool PeriodicChecking { get; set; } = false;

    [JsonProperty("periodic_checking_interval")]
    public int PeriodicCheckingInterval { get; set; } = 5;

    [JsonProperty("periodic_checking_checkall")]
    public bool CheckAllAccounts { get; set; } = false;

    [JsonProperty("auto_confirm_market_transactions")]
    public bool AutoConfirmMarketTransactions { get; set; } = false;

    [JsonProperty("auto_confirm_trades")]
    public bool AutoConfirmTrades { get; set; } = false;

    private static Manifest _manifest { get; set; }

    public static string GetExecutableDir()
    {
        return Path.GetDirectoryName(System.Reflection.Assembly.GetEntryAssembly().Location);
    }

    public static Manifest GetManifest(bool forceLoad = false)
    {
        // Check if already staticly loaded
        if (_manifest != null && !forceLoad)
        {
            return _manifest;
        }

        // Find config dir and manifest file
        string maFile = Program.SteamGuardPath + "/manifest.json";

        // If there's no config dir, create it
        if (!Directory.Exists(Program.SteamGuardPath))
        {
            _manifest = _generateNewManifest();
            return _manifest;
        }

        // If there's no manifest, create it
        if (!File.Exists(maFile))
        {
            if (Program.Verbose) Console.WriteLine("warn: No manifest file found at {0}", maFile);
            _manifest = _generateNewManifest(true);
            return _manifest;
        }

        try
        {
            string manifestContents = File.ReadAllText(maFile);
            _manifest = JsonConvert.DeserializeObject<Manifest>(manifestContents);

            if (_manifest.Encrypted && _manifest.Entries.Count == 0)
            {
                _manifest.Encrypted = false;
                _manifest.Save();
            }

            if (_manifest.Encrypted)
            {
                throw new NotSupportedException("Encrypted maFiles are not supported at this time.");
            }

            _manifest.RecomputeExistingEntries();

            return _manifest;
        }
        catch (Exception ex)
        {
            Console.WriteLine("error: Could not open manifest file: {0}", ex.ToString());
            return null;
        }
    }

    private static Manifest _generateNewManifest(bool scanDir = false)
    {
        if (Program.Verbose) Console.WriteLine("Generating new manifest...");

        // No directory means no manifest file anyways.
        Manifest newManifest = new Manifest();
        newManifest.Encrypted = false;
        newManifest.PeriodicCheckingInterval = 5;
        newManifest.PeriodicChecking = false;
        newManifest.AutoConfirmMarketTransactions = false;
        newManifest.AutoConfirmTrades = false;
        newManifest.Entries = new List<ManifestEntry>();
        newManifest.FirstRun = true;

        // Take a pre-manifest version and generate a manifest for it.
        if (scanDir)
        {

            if (Directory.Exists(Program.SteamGuardPath))
            {
                DirectoryInfo dir = new DirectoryInfo(Program.SteamGuardPath);
                var files = dir.GetFiles();

                foreach (var file in files)
                {
                    if (file.Extension != ".maFile") continue;

                    string contents = File.ReadAllText(file.FullName);
                    try
                    {
                        SteamGuardAccount account = JsonConvert.DeserializeObject<SteamGuardAccount>(contents);
                        ManifestEntry newEntry = new ManifestEntry()
                        {
                            Filename = file.Name,
                            SteamID = account.Session.SteamID
                        };
                        newManifest.Entries.Add(newEntry);
                    }
                    catch (Exception)
                    {
                    }
                }

                if (newManifest.Entries.Count > 0)
                {
                    newManifest.Save();
                    newManifest.PromptSetupPassKey("This version of SDA has encryption. Please enter a passkey below, or hit cancel to remain unencrypted");
                }
            }
        }

        if (newManifest.Save())
        {
            return newManifest;
        }

        return null;
    }

    public class IncorrectPassKeyException : Exception { }
    public class ManifestNotEncryptedException : Exception { }

    public string PromptForPassKey()
    {
        if (!this.Encrypted)
        {
            throw new ManifestNotEncryptedException();
        }

        bool passKeyValid = false;
        string passKey = "";
        while (!passKeyValid)
        {
            Console.WriteLine("Please enter encryption password: ");
            passKey = Console.ReadLine();
            if (passKey == "")
                continue;
            passKeyValid = this.VerifyPasskey(passKey);
            if (!passKeyValid)
            {
                Console.WriteLine("Incorrect.");
            }
        }
        return passKey;
    }

    public string PromptSetupPassKey(string initialPrompt = "Enter passkey, or hit cancel to remain unencrypted.")
    {
        Console.Write("Would you like to use encryption? [Y/n] ");
        string doEncryptAnswer = Console.ReadLine();
        if (doEncryptAnswer == "n" || doEncryptAnswer == "N")
        {
            Console.WriteLine("WARNING: You chose to not encrypt your files. Doing so imposes a security risk for yourself. If an attacker were to gain access to your computer, they could completely lock you out of your account and steal all your items.");
            return null;
        }

        string newPassKey = "";
        string confirmPassKey = "";
        do
        {
            Console.Write("Enter passkey: ");
            newPassKey = Console.ReadLine();
            Console.Write("Confirm passkey: ");
            confirmPassKey = Console.ReadLine();

            if (newPassKey != confirmPassKey)
            {
                Console.WriteLine("Passkeys do not match.");
            }
        } while (newPassKey != confirmPassKey);

        if (!this.ChangeEncryptionKey(null, newPassKey))
        {
            Console.WriteLine("Unable to set passkey.");
            return null;
        }
        else
        {
            Console.WriteLine("Passkey successfully set.");
        }

        return newPassKey;
    }

    public SteamAuth.SteamGuardAccount[] GetAllAccounts(string passKey = null, int limit = -1)
    {
        if (passKey == null && this.Encrypted) return new SteamGuardAccount[0];

        List<SteamAuth.SteamGuardAccount> accounts = new List<SteamAuth.SteamGuardAccount>();
        foreach (var entry in this.Entries)
        {
            string fileText = "";
            Stream stream = null;
            FileStream fileStream = File.OpenRead(Path.Combine(Program.SteamGuardPath, entry.Filename));

            if (this.Encrypted)
            {
                //string decryptedText = FileEncryptor.DecryptData(passKey, entry.Salt, entry.IV, fileText);
            }
            else
            {
                stream = fileStream;
            }

            byte[] b = new byte[1024];
            StringBuilder sb = new StringBuilder();
            while (stream.Read(b,0,b.Length) > 0)
            {
                sb.Append(Encoding.UTF8.GetString(b));
            }
            stream.Close();
            fileText = sb.ToString();

            var account = JsonConvert.DeserializeObject<SteamAuth.SteamGuardAccount>(fileText);
            if (account == null) continue;
            accounts.Add(account);

            if (limit != -1 && limit >= accounts.Count)
                break;
        }

        return accounts.ToArray();
    }

    public bool ChangeEncryptionKey(string oldKey, string newKey)
    {
        throw new NotSupportedException("Encrypted maFiles are not supported at this time.");
    }

    public bool VerifyPasskey(string passkey)
    {
        if (!this.Encrypted || this.Entries.Count == 0) return true;

        var accounts = this.GetAllAccounts(passkey, 1);
        return accounts != null && accounts.Length == 1;
    }

    public bool RemoveAccount(SteamGuardAccount account, bool deleteMaFile = true)
    {
        ManifestEntry entry = (from e in this.Entries where e.SteamID == account.Session.SteamID select e).FirstOrDefault();
        if (entry == null) return true; // If something never existed, did you do what they asked?

        string filename = Path.Combine(Program.SteamGuardPath, entry.Filename);
        this.Entries.Remove(entry);

        if (this.Entries.Count == 0)
        {
            this.Encrypted = false;
        }

        if (this.Save() && deleteMaFile)
        {
            try
            {
                File.Delete(filename);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        return false;
    }

    public bool SaveAccount(SteamGuardAccount account, bool encrypt, string passKey = null)
    {
        if (encrypt && String.IsNullOrEmpty(passKey)) return false;
        if (!encrypt && this.Encrypted) return false;

        string salt = null;
        string iV = null;
        string jsonAccount = JsonConvert.SerializeObject(account);

        if (encrypt)
        {
            throw new NotSupportedException("Encrypted maFiles are not supported at this time.");
        }


        string filename = account.Session.SteamID.ToString() + ".maFile";

        ManifestEntry newEntry = new ManifestEntry()
        {
            SteamID = account.Session.SteamID,
            IV = iV,
            Salt = salt,
            Filename = filename
        };

        bool foundExistingEntry = false;
        for (int i = 0; i < this.Entries.Count; i++)
        {
            if (this.Entries[i].SteamID == account.Session.SteamID)
            {
                this.Entries[i] = newEntry;
                foundExistingEntry = true;
                break;
            }
        }

        if (!foundExistingEntry)
        {
            this.Entries.Add(newEntry);
        }

        bool wasEncrypted = this.Encrypted;
        this.Encrypted = encrypt || this.Encrypted;

        if (!this.Save())
        {
            this.Encrypted = wasEncrypted;
            return false;
        }

        try
        {
            File.WriteAllText(Program.SteamGuardPath + filename, jsonAccount);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    public bool Save()
    {

        string filename = Program.SteamGuardPath + "manifest.json";
        if (!Directory.Exists(Program.SteamGuardPath))
        {
            try
            {
                Directory.CreateDirectory(Program.SteamGuardPath);
            }
            catch (Exception)
            {
                return false;
            }
        }

        try
        {
            string contents = JsonConvert.SerializeObject(this);
            File.WriteAllText(filename, contents);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private void RecomputeExistingEntries()
    {
        List<ManifestEntry> newEntries = new List<ManifestEntry>();

        foreach (var entry in this.Entries)
        {
            string filename = Path.Combine(Program.SteamGuardPath, entry.Filename);

            if (File.Exists(filename))
            {
                newEntries.Add(entry);
            }
        }

        this.Entries = newEntries;

        if (this.Entries.Count == 0)
        {
            this.Encrypted = false;
        }
    }

    public void MoveEntry(int from, int to)
    {
        if (from < 0 || to < 0 || from > Entries.Count || to > Entries.Count - 1) return;
        ManifestEntry sel = Entries[from];
        Entries.RemoveAt(from);
        Entries.Insert(to, sel);
        Save();
    }

    public class ManifestEntry
    {
        [JsonProperty("encryption_iv")]
        public string IV { get; set; }

        [JsonProperty("encryption_salt")]
        public string Salt { get; set; }

        [JsonProperty("filename")]
        public string Filename { get; set; }

        [JsonProperty("steamid")]
        public ulong SteamID { get; set; }
    }

    /*
     Crypto Functions
    */

    /// <summary>
    /// Returns an 8-byte cryptographically random salt in base64 encoding
    /// </summary>
    /// <returns></returns>
    public static string GetRandomSalt()
    {
        byte[] salt = new byte[SALT_LENGTH];
        using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(salt);
        }
        return Convert.ToBase64String(salt);
    }

    /// <summary>
    /// Returns a 16-byte cryptographically random initialization vector (IV) in base64 encoding
    /// </summary>
    /// <returns></returns>
    public static string GetInitializationVector()
    {
        byte[] IV = new byte[IV_LENGTH];
        using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(IV);
        }
        return Convert.ToBase64String(IV);
    }


    /// <summary>
    /// Generates an encryption key derived using a password, a random salt, and specified number of rounds of PBKDF2
    /// </summary>
    /// <param name="password"></param>
    /// <param name="salt"></param>
    /// <returns></returns>
    private static byte[] GetEncryptionKey(string password, string salt)
    {
        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Password is empty");
        }
        if (string.IsNullOrEmpty(salt))
        {
            throw new ArgumentException("Salt is empty");
        }
        using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, Convert.FromBase64String(salt), PBKDF2_ITERATIONS))
        {
            return pbkdf2.GetBytes(KEY_SIZE_BYTES);
        }
    }
}
