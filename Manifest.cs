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

    public static Manifest GetManifest(bool forceLoad = false)
    {
        // Check if already staticly loaded
        if (_manifest != null && !forceLoad)
        {
            return _manifest;
        }

        // Find config dir and manifest file
        string maFile = Path.Combine(Program.SteamGuardPath, "manifest.json");

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
	        bool? createNewManifest = Program.SteamGuardPath ==
	                                  Program.defaultSteamGuardPath.Replace("~", Environment.GetEnvironmentVariable("HOME")) ? true : (bool?) null;
	        while (createNewManifest == null)
	        {
		        Console.Write($"Generate new manifest.json in {Program.SteamGuardPath}? [Y/n]");
		        var answer = Console.ReadLine();
		        if (answer != null)
		        	createNewManifest = !answer.StartsWith("n") && !answer.StartsWith("N");
	        }
	        if ((bool) createNewManifest)
	        {
		        _manifest = _generateNewManifest(true);
		        return _manifest;
	        }
	        return null;
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
                    catch (Exception ex)
                    {
                        if (Program.Verbose) Console.WriteLine("warn: {0}", ex.Message);
                    }
                }

                if (newManifest.Entries.Count > 0)
                {
                    newManifest.Save();
                    newManifest.PromptSetupPassKey(true);
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

    // TODO: move PromptForPassKey to Program.cs
    // TODO: make PromptForPassKey more secure
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

    // TODO: move PromptSetupPassKey to Program.cs
    public string PromptSetupPassKey(bool inAccountSetupProcess = false)
    {
        if (inAccountSetupProcess)
        {
            Console.Write("Would you like to use encryption? [Y/n] ");
            string doEncryptAnswer = Console.ReadLine();
            if (doEncryptAnswer == "n" || doEncryptAnswer == "N")
            {
                Console.WriteLine("WARNING: You chose to not encrypt your files. Doing so imposes a security risk for yourself. If an attacker were to gain access to your computer, they could completely lock you out of your account and steal all your items.");
                return null;
            }
        }

        string newPassKey = "";
        string confirmPassKey = "";
        do
        {
            Console.Write("Enter" + (inAccountSetupProcess ? " " : " new ") + "passkey: ");
            newPassKey = Console.ReadLine();
            Console.Write("Confirm" + (inAccountSetupProcess ? " " : " new ") + "passkey: ");
            confirmPassKey = Console.ReadLine();

            if (newPassKey != confirmPassKey)
            {
                Console.WriteLine("Passkeys do not match.");
            }
        } while (newPassKey != confirmPassKey || newPassKey == "");

        return newPassKey;
    }

    public SteamAuth.SteamGuardAccount[] GetAllAccounts(string passKey = null, int limit = -1)
    {
        if (passKey == null && this.Encrypted) return new SteamGuardAccount[0];

        List<SteamAuth.SteamGuardAccount> accounts = new List<SteamAuth.SteamGuardAccount>();
        foreach (var entry in this.Entries)
        {
            var account = GetAccount(entry, passKey);
            if (account == null) continue;
            accounts.Add(account);

            if (limit != -1 && limit >= accounts.Count)
                break;
        }

        return accounts.ToArray();
    }

    public SteamGuardAccount GetAccount(ManifestEntry entry, string passKey = null)
    {
        string fileText = "";
        Stream stream = null;
        RijndaelManaged aes256;

        if (this.Encrypted)
        {
            MemoryStream ms = new MemoryStream(Convert.FromBase64String(File.ReadAllText(Path.Combine(Program.SteamGuardPath, entry.Filename))));
            byte[] key = GetEncryptionKey(passKey, entry.Salt);

            aes256 = new RijndaelManaged
            {
                IV = Convert.FromBase64String(entry.IV),
                Key = key,
                Padding = PaddingMode.PKCS7,
                Mode = CipherMode.CBC
            };

            ICryptoTransform decryptor = aes256.CreateDecryptor(aes256.Key, aes256.IV);
            stream = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        }
        else
        {
            FileStream fileStream = File.OpenRead(Path.Combine(Program.SteamGuardPath, entry.Filename));
            stream = fileStream;
        }

        if (Program.Verbose) Console.WriteLine("Decrypting...");
        using (StreamReader reader = new StreamReader(stream))
        {
            fileText = reader.ReadToEnd();
        }
        stream.Close();

        return JsonConvert.DeserializeObject<SteamAuth.SteamGuardAccount>(fileText);
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

    public bool SaveAccount(SteamGuardAccount account, bool encrypt, string passKey = null, string salt = null, string iV = null)
    {
        if (encrypt && (String.IsNullOrEmpty(passKey) || String.IsNullOrEmpty(salt) || String.IsNullOrEmpty(iV))) return false;

        string jsonAccount = JsonConvert.SerializeObject(account);

        string filename = account.Session.SteamID.ToString() + ".maFile";
		if (Program.Verbose) Console.WriteLine($"Saving account {account.AccountName} to {filename}...");

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
        this.Encrypted = encrypt;

        if (!this.Save())
        {
            this.Encrypted = wasEncrypted;
            return false;
        }

        try
        {
            Stream stream = null;
            MemoryStream ms = null;
            RijndaelManaged aes256;

            if (encrypt)
            {
                ms = new MemoryStream();
                byte[] key = GetEncryptionKey(passKey, newEntry.Salt);

                aes256 = new RijndaelManaged
                {
                    IV = Convert.FromBase64String(newEntry.IV),
                    Key = key,
                    Padding = PaddingMode.PKCS7,
                    Mode = CipherMode.CBC
                };

                ICryptoTransform encryptor = aes256.CreateEncryptor(aes256.Key, aes256.IV);
                stream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
            }
            else
            {
				// An unencrypted maFile is shorter than the encrypted version,
				// so when an unencrypted maFile gets written this way, the file does not get wiped
				// leaving encrypted text after the final } bracket. Deleting and recreating the file fixes this.
				File.Delete(Path.Combine(Program.SteamGuardPath, newEntry.Filename));
                stream = File.OpenWrite(Path.Combine(Program.SteamGuardPath, newEntry.Filename)); // open or create
            }

            using (StreamWriter writer = new StreamWriter(stream))
            {
                writer.Write(jsonAccount);
            }

            if (encrypt)
            {
                File.WriteAllText(Path.Combine(Program.SteamGuardPath, newEntry.Filename), Convert.ToBase64String(ms.ToArray()));
            }

            stream.Close();
            return true;
        }
        catch (Exception ex)
        {
            if (Program.Verbose) Console.WriteLine("error: {0}", ex.ToString());
            return false;
        }
    }

    public bool Save()
    {
        string filename = Path.Combine(Program.SteamGuardPath, "manifest.json");
        if (!Directory.Exists(Program.SteamGuardPath))
        {
            try
            {
				if (Program.Verbose) Console.WriteLine("Creating {0}", Program.SteamGuardPath);
                Directory.CreateDirectory(Program.SteamGuardPath);
            }
            catch (Exception ex)
            {
				if (Program.Verbose) Console.WriteLine($"error: {ex.Message}");
                return false;
            }
        }

        try
        {
            string contents = JsonConvert.SerializeObject(this);
            File.WriteAllText(filename, contents);
            return true;
        }
        catch (Exception ex)
        {
			if (Program.Verbose) Console.WriteLine($"error: {ex.Message}");
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
