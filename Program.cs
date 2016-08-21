using Newtonsoft.Json;
using SteamAuth;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

public static class Program
{
    const string defaultSteamGuardPath = "~/maFiles";

    public static string SteamGuardPath { get; set; } = defaultSteamGuardPath;

    /// <summary>
    ///   The main entry point for the application
    /// </summary>
    [STAThread]
    public static void Main(string[] args)
    {
        if (args.Contains("--help") || args.Contains("-h"))
        {
            Console.WriteLine("steamguard-cli - v0.0");
            Console.WriteLine();
            Console.WriteLine("--help, -h   Display this help message.");
            return;
        }

        SteamGuardPath = SteamGuardPath.Replace("~", Environment.GetEnvironmentVariable("HOME"));
        if (!Directory.Exists(SteamGuardPath))
        {
            if (SteamGuardPath == defaultSteamGuardPath.Replace("~", Environment.GetEnvironmentVariable("HOME")))
            {
                Console.WriteLine("warn: {0} does not exist, creating...", SteamGuardPath);
                Directory.CreateDirectory(SteamGuardPath);
            }
            else
            {
                Console.WriteLine("error: {0} does not exist.", SteamGuardPath);
                return;
            }
        }
    }
}

public class Manifest
{
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
        string maDir = Manifest.GetExecutableDir() + "/maFiles/";
        string maFile = maDir + "manifest.json";

        // If there's no config dir, create it
        if (!Directory.Exists(maDir))
        {
            _manifest = _generateNewManifest();
            return _manifest;
        }

        // If there's no manifest, create it
        if (!File.Exists(maFile))
        {
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

            _manifest.RecomputeExistingEntries();

            return _manifest;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static Manifest _generateNewManifest(bool scanDir = false)
    {
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
            string maDir = Manifest.GetExecutableDir() + "/maFiles/";
            if (Directory.Exists(maDir))
            {
                DirectoryInfo dir = new DirectoryInfo(maDir);
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
        string passKey = null;
        while (!passKeyValid)
        {
            InputForm passKeyForm = new InputForm("Please enter your encryption passkey.", true);
            passKeyForm.ShowDialog();
            if (!passKeyForm.Canceled)
            {
                passKey = passKeyForm.txtBox.Text;
                passKeyValid = this.VerifyPasskey(passKey);
                if (!passKeyValid)
                {
                    MessageBox.Show("That passkey is invalid.");
                }
            }
            else
            {
                return null;
            }
        }
        return passKey;
    }

    public string PromptSetupPassKey(string initialPrompt = "Enter passkey, or hit cancel to remain unencrypted.")
    {
        InputForm newPassKeyForm = new InputForm(initialPrompt);
        newPassKeyForm.ShowDialog();
        if (newPassKeyForm.Canceled || newPassKeyForm.txtBox.Text.Length == 0)
        {
            MessageBox.Show("WARNING: You chose to not encrypt your files. Doing so imposes a security risk for yourself. If an attacker were to gain access to your computer, they could completely lock you out of your account and steal all your items.");
            return null;
        }

        InputForm newPassKeyForm2 = new InputForm("Confirm new passkey.");
        newPassKeyForm2.ShowDialog();
        if (newPassKeyForm2.Canceled)
        {
            MessageBox.Show("WARNING: You chose to not encrypt your files. Doing so imposes a security risk for yourself. If an attacker were to gain access to your computer, they could completely lock you out of your account and steal all your items.");
            return null;
        }

        string newPassKey = newPassKeyForm.txtBox.Text;
        string confirmPassKey = newPassKeyForm2.txtBox.Text;

        if (newPassKey != confirmPassKey)
        {
            MessageBox.Show("Passkeys do not match.");
            return null;
        }

        if (!this.ChangeEncryptionKey(null, newPassKey))
        {
            MessageBox.Show("Unable to set passkey.");
            return null;
        }
        else
        {
            MessageBox.Show("Passkey successfully set.");
        }

        return newPassKey;
    }

    public SteamAuth.SteamGuardAccount[] GetAllAccounts(string passKey = null, int limit = -1)
    {
        if (passKey == null && this.Encrypted) return new SteamGuardAccount[0];
        string maDir = Manifest.GetExecutableDir() + "/maFiles/";

        List<SteamAuth.SteamGuardAccount> accounts = new List<SteamAuth.SteamGuardAccount>();
        foreach (var entry in this.Entries)
        {
            string fileText = File.ReadAllText(maDir + entry.Filename);
            if (this.Encrypted)
            {
                string decryptedText = FileEncryptor.DecryptData(passKey, entry.Salt, entry.IV, fileText);
                if (decryptedText == null) return new SteamGuardAccount[0];
                fileText = decryptedText;
            }

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
        if (this.Encrypted)
        {
            if (!this.VerifyPasskey(oldKey))
            {
                return false;
            }
        }
        bool toEncrypt = newKey != null;

        string maDir = Manifest.GetExecutableDir() + "/maFiles/";
        for (int i = 0; i < this.Entries.Count; i++)
        {
            ManifestEntry entry = this.Entries[i];
            string filename = maDir + entry.Filename;
            if (!File.Exists(filename)) continue;

            string fileContents = File.ReadAllText(filename);
            if (this.Encrypted)
            {
                fileContents = FileEncryptor.DecryptData(oldKey, entry.Salt, entry.IV, fileContents);
            }

            string newSalt = null;
            string newIV = null;
            string toWriteFileContents = fileContents;

            if (toEncrypt)
            {
                newSalt = FileEncryptor.GetRandomSalt();
                newIV = FileEncryptor.GetInitializationVector();
                toWriteFileContents = FileEncryptor.EncryptData(newKey, newSalt, newIV, fileContents);
            }

            File.WriteAllText(filename, toWriteFileContents);
            entry.IV = newIV;
            entry.Salt = newSalt;
        }

        this.Encrypted = toEncrypt;

        this.Save();
        return true;
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

        string maDir = Manifest.GetExecutableDir() + "/maFiles/";
        string filename = maDir + entry.Filename;
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
            salt = FileEncryptor.GetRandomSalt();
            iV = FileEncryptor.GetInitializationVector();
            string encrypted = FileEncryptor.EncryptData(passKey, salt, iV, jsonAccount);
            if (encrypted == null) return false;
            jsonAccount = encrypted;
        }

        string maDir = Manifest.GetExecutableDir() + "/maFiles/";
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
            File.WriteAllText(maDir + filename, jsonAccount);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    public bool Save()
    {
        string maDir = Manifest.GetExecutableDir() + "/maFiles/";
        string filename = maDir + "manifest.json";
        if (!Directory.Exists(maDir))
        {
            try
            {
                Directory.CreateDirectory(maDir);
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
        string maDir = Manifest.GetExecutableDir() + "/maFiles/";

        foreach (var entry in this.Entries)
        {
            string filename = maDir + entry.Filename;
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
}

/// <summary>
/// This class provides the controls that will encrypt and decrypt the *.maFile files
///
/// Passwords entered will be passed into 100k rounds of PBKDF2 (RFC2898) with a cryptographically random salt.
/// The generated key will then be passed into AES-256 (RijndalManaged) which will encrypt the data
/// in cypher block chaining (CBC) mode, and then write both the PBKDF2 salt and encrypted data onto the disk.
/// </summary>
public static class FileEncryptor
{
    private const int PBKDF2_ITERATIONS = 50000; //Set to 50k to make program not unbearably slow. May increase in future.
    private const int SALT_LENGTH = 8;
    private const int KEY_SIZE_BYTES = 32;
    private const int IV_LENGTH = 16;

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
    ///
    /// TODO: pass in password via SecureString?
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

    /// <summary>
    /// Tries to decrypt and return data given an encrypted base64 encoded string. Must use the same
    /// password, salt, IV, and ciphertext that was used during the original encryption of the data.
    /// </summary>
    /// <param name="password"></param>
    /// <param name="passwordSalt"></param>
    /// <param name="IV">Initialization Vector</param>
    /// <param name="encryptedData"></param>
    /// <returns></returns>
    public static string DecryptData(string password, string passwordSalt, string IV, string encryptedData)
    {
        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Password is empty");
        }
        if (string.IsNullOrEmpty(passwordSalt))
        {
            throw new ArgumentException("Salt is empty");
        }
        if (string.IsNullOrEmpty(IV))
        {
            throw new ArgumentException("Initialization Vector is empty");
        }
        if (string.IsNullOrEmpty(encryptedData))
        {
            throw new ArgumentException("Encrypted data is empty");
        }

        byte[] cipherText = Convert.FromBase64String(encryptedData);
        byte[] key = GetEncryptionKey(password, passwordSalt);
        string plaintext = null;

        using (RijndaelManaged aes256 = new RijndaelManaged())
        {
            aes256.IV = Convert.FromBase64String(IV);
            aes256.Key = key;
            aes256.Padding = PaddingMode.PKCS7;
            aes256.Mode = CipherMode.CBC;

            //create decryptor to perform the stream transform
            ICryptoTransform decryptor = aes256.CreateDecryptor(aes256.Key, aes256.IV);

            //wrap in a try since a bad password yields a bad key, which would throw an exception on decrypt
            try
            {
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            catch (CryptographicException)
            {
                plaintext = null;
            }
        }
        return plaintext;
    }

    /// <summary>
    /// Encrypts a string given a password, salt, and initialization vector, then returns result in base64 encoded string.
    ///
    /// To retrieve this data, you must decrypt with the same password, salt, IV, and cyphertext that was used during encryption
    /// </summary>
    /// <param name="password"></param>
    /// <param name="passwordSalt"></param>
    /// <param name="IV"></param>
    /// <param name="plaintext"></param>
    /// <returns></returns>
    public static string EncryptData(string password, string passwordSalt, string IV, string plaintext)
    {
        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Password is empty");
        }
        if (string.IsNullOrEmpty(passwordSalt))
        {
            throw new ArgumentException("Salt is empty");
        }
        if (string.IsNullOrEmpty(IV))
        {
            throw new ArgumentException("Initialization Vector is empty");
        }
        if (string.IsNullOrEmpty(plaintext))
        {
            throw new ArgumentException("Plaintext data is empty");
        }
        byte[] key = GetEncryptionKey(password, passwordSalt);
        byte[] ciphertext;

        using (RijndaelManaged aes256 = new RijndaelManaged())
        {
            aes256.Key = key;
            aes256.IV = Convert.FromBase64String(IV);
            aes256.Padding = PaddingMode.PKCS7;
            aes256.Mode = CipherMode.CBC;

            ICryptoTransform encryptor = aes256.CreateEncryptor(aes256.Key, aes256.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncypt = new StreamWriter(csEncrypt))
                    {
                        swEncypt.Write(plaintext);
                    }
                    ciphertext = msEncrypt.ToArray();
                }
            }
        }
        return Convert.ToBase64String(ciphertext);
    }
}
