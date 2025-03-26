using System;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.Win32;
using System.Diagnostics;
using System.Security.Cryptography;

namespace DirectoryArchiver
{
    /// <summary>
    /// Provides functionality to encrypt directories into password-protected 7-Zip archives.
    /// </summary>
    public static class Program
    {
        // --- Constants ---

        #region Configuration
        private const int DefaultPasswordLength = 16;
        #endregion

        #region 7-Zip Settings
        private const string SevenZipArchiverArgsTemplate = "a -t7z -mx9 -m0=LZMA2 -md=128m -mfb=64 -mmt=on -mhe=on -ms=off -sdel -sse -spd -ssw -p{0} \"{1}\" \"{2}\"";
        private const string SevenZipArchiverExtension = ".7z";
        private const string SevenZipExecutableName = "7z.exe";
        private const string SevenZipSimpleTestArgument = "-h";
        #endregion

        #region Logging & Output
        private const string LogFileName = "archives.log";
        #endregion

        #region Registry & Paths
        private static readonly string[] DefaultSevenZipExePaths =
        {
            @"C:\Program Files\7-Zip\" + SevenZipExecutableName,
            @"C:\Program Files (x86)\7-Zip\" + SevenZipExecutableName
        };
        private const string UninstallRegistryPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        private const string SevenZipSpecificRegistryPath = @"SOFTWARE\7-Zip";
        #endregion

        #region Security
        private const string PasswordChars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()_-+=[]{}";
        #endregion

        // --- End Constants ---

        /// <summary>
        /// Main entry point for the application.
        /// </summary>
        static void Main()
        {
            Console.Title = "Directory Encryptor Utility";

            // --- Locate 7-Zip ---
            LogInfo("Attempting to locate 7-Zip executable...");
            string archiverPath = GetSevenZipExecutablePath();
            if (string.IsNullOrEmpty(archiverPath))
            {
                LogError("7-Zip executable not found.");
                LogInfo("Please ensure 7-Zip is installed and its path is either in the system PATH environment variable,");
                LogInfo($"standard locations ({string.Join(", ", DefaultSevenZipExePaths)}), or registered correctly.");
                Prompt("Press any key to exit...");
                Console.ReadKey();
                return;
            }
            LogSuccess($"Using 7-Zip: {archiverPath}");
            Console.WriteLine(); // Add visual spacing

            // --- Get User Input ---
            string sourceDirectoryPath = Prompt("Enter the path to the source directory (containing subdirectories to archive):");
            if (!Directory.Exists(sourceDirectoryPath))
            {
                LogError($"Source directory not found: {sourceDirectoryPath}");
                Prompt("Press any key to exit...");
                Console.ReadKey();
                return;
            }

            string outputDirectoryPath = Prompt("Enter the path for saving the archives:");
            try
            {
                Directory.CreateDirectory(outputDirectoryPath);
                LogInfo($"Output directory set to: '{outputDirectoryPath}'");
            }
            catch (Exception ex)
            {
                LogError($"Error creating output directory '{outputDirectoryPath}': {ex.Message}");
                Prompt("Press any key to exit...");
                Console.ReadKey();
                return;
            }

            string logFilePath = Path.Combine(outputDirectoryPath, LogFileName);
            LogInfo($"Logging archive details to: {logFilePath}");
            Console.WriteLine();

            // --- Process Directories ---
            string[] subDirectories;
            try
            {
                subDirectories = Directory.GetDirectories(sourceDirectoryPath, "*", SearchOption.TopDirectoryOnly);
            }
            catch (Exception ex)
            {
                LogError($"Error reading subdirectories from '{sourceDirectoryPath}': {ex.Message}");
                Prompt("Press any key to exit...");
                Console.ReadKey();
                return;
            }

            if (subDirectories.Length == 0)
            {
                LogWarning($"No subdirectories found directly within '{sourceDirectoryPath}'. Nothing to process.");
            }
            else
            {
                LogInfo($"Found {subDirectories.Length} director{(subDirectories.Length == 1 ? "y" : "ies")} to process...");
                Console.WriteLine();

                int successCount = 0;
                int errorCount = 0;

                foreach (string currentDirectory in subDirectories)
                {
                    string directoryName = new DirectoryInfo(currentDirectory).Name;
                    LogInfo($"Processing directory: '{directoryName}' ...");

                    try
                    {
                        string password = GenerateSecurePassword(DefaultPasswordLength);
                        string archiveName = directoryName + SevenZipArchiverExtension;
                        string archivePath = Path.Combine(outputDirectoryPath, archiveName);
                        string arguments = string.Format(SevenZipArchiverArgsTemplate, password, archivePath, currentDirectory);

                        ProcessStartInfo processInfo = new ProcessStartInfo
                        {
                            FileName = archiverPath,
                            Arguments = arguments,
                            WindowStyle = ProcessWindowStyle.Hidden,
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            CreateNoWindow = true
                        };

                        using (Process process = new Process { StartInfo = processInfo })
                        {
                            StringBuilder errorOutput = new StringBuilder();
                            process.ErrorDataReceived += (sender, e) => { if (e.Data != null) errorOutput.AppendLine(e.Data); };

                            process.Start();
                            process.BeginErrorReadLine();

                            process.WaitForExit();

                            if (process.ExitCode == 0)
                            {
                                LogArchiveInfo(logFilePath, archivePath, password);
                                LogSuccess($"Archived '{directoryName}' to '{archivePath}' and source directory deleted by 7-Zip.");
                                successCount++;
                            }
                            else
                            {
                                LogError($"Archiving '{directoryName}' failed. 7-Zip exited with code {process.ExitCode}. Source directory NOT deleted.");
                                string errors = errorOutput.ToString().Trim();
                                if (!string.IsNullOrWhiteSpace(errors))
                                {
                                    LogError($"7-Zip Error Output:\n{errors}");
                                }
                                errorCount++;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        LogError($"Critical error processing directory '{directoryName}': {ex.Message}");
                        errorCount++;
                    }

                    Console.WriteLine();
                }

                LogInfo($"Processing finished. Successful: {successCount}, Failed: {errorCount}.");
            }

            Prompt("Press any key to exit...");
            Console.ReadKey();
        }

        #region Console Output Helpers
        /// <summary>
        /// Logs an informational message to the console.
        /// </summary>
        /// <param name="message">The message to log.</param>
        private static void LogInfo(string message)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"[INFO] {message}");
            Console.ResetColor();
        }

        /// <summary>
        /// Logs a success message to the console.
        /// </summary>
        /// <param name="message">The message to log.</param>
        private static void LogSuccess(string message)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[SUCC] {message}");
            Console.ResetColor();
        }

        /// <summary>
        /// Logs a warning message to the console.
        /// </summary>
        /// <param name="message">The message to log.</param>
        private static void LogWarning(string message)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[WARN] {message}");
            Console.ResetColor();
        }

        /// <summary>
        /// Logs an error message to the console.
        /// </summary>
        /// <param name="message">The message to log.</param>
        private static void LogError(string message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[ERROR] {message}");
            Console.ResetColor();
        }

        /// <summary>
        /// Prompts the user for input and returns the response.
        /// </summary>
        /// <param name="message">The prompt message displayed to the user.</param>
        /// <returns>The string entered by the user.</returns>
        private static string Prompt(string message)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"[>] {message} "); // Use Write for inline input
            Console.ResetColor();
            return Console.ReadLine();
        }

        /// <summary>
        /// Logs a debug or step message to the console. Useful for detailed tracing.
        /// </summary>
        /// <param name="message">The message to log.</param>
        private static void LogDebug(string message)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"[DEBUG] {message}");
            Console.ResetColor();
        }
        #endregion

        /// <summary>
        /// Generates a cryptographically secure random password of a specified length.
        /// </summary>
        /// <param name="length">The desired length of the password.</param>
        /// <returns>A securely generated random password string.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown if length is less than 1.</exception>
        private static string GenerateSecurePassword(int length)
        {
            if (length < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(length), "Password length must be at least 1.");
            }

            int validCharsCount = PasswordChars.Length;
            StringBuilder passwordBuilder = new StringBuilder(length);

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                byte[] randomBytes = new byte[4];

                for (int i = 0; i < length; i++)
                {
                    rng.GetBytes(randomBytes);
                    uint randomNumber = BitConverter.ToUInt32(randomBytes, 0);
                    int index = (int)(randomNumber % validCharsCount);
                    passwordBuilder.Append(PasswordChars[index]);
                }
            }

            return passwordBuilder.ToString();
        }

        /// <summary>
        /// Appends archive information (path and password) to the specified log file.
        /// </summary>
        /// <param name="logFilePath">The full path to the log file.</param>
        /// <param name="archivePath">The full path to the created archive file.</param>
        /// <param name="password">The password used for the archive.</param>
        private static void LogArchiveInfo(string logFilePath, string archivePath, string password)
        {
            try
            {
                string logEntry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss}|{archivePath}|{password}{Environment.NewLine}";
                File.AppendAllText(logFilePath, logEntry, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                LogWarning($"Failed to write log entry for '{Path.GetFileName(archivePath)}'. Error: {ex.Message}");
            }
        }

        /// <summary>
        /// Attempts to locate the 7z.exe executable using multiple strategies:
        /// 1. Default installation paths.
        /// 2. Windows Uninstall registry.
        /// 3. Specific 7-Zip registry key.
        /// 4. System PATH environment variable.
        /// </summary>
        /// <returns>The full path to 7z.exe or just "7z.exe" (if found in PATH), otherwise null.</returns>
        private static string GetSevenZipExecutablePath()
        {
            string foundPath;

            // 1. Check default installation paths
            LogDebug("Checking default 7-Zip installation paths...");
            foundPath = DefaultSevenZipExePaths.FirstOrDefault(File.Exists);
            if (!string.IsNullOrEmpty(foundPath))
            {
                LogDebug($"Found 7-Zip at default location: {foundPath}");
                return foundPath;
            }
            LogDebug("7-Zip not found in default locations.");

            // 2. Search Windows Uninstall registry keys
            LogDebug("Checking Windows Uninstall registry keys...");
            foundPath = SearchUninstallRegistryFor7Zip();
            if (!string.IsNullOrEmpty(foundPath))
            {
                LogDebug($"Found 7-Zip via Uninstall registry: {foundPath}");
                return foundPath;
            }
            LogDebug("7-Zip path not found in Uninstall registry keys.");

            // 3. Check the specific 7-Zip registry key
            LogDebug("Checking specific 7-Zip registry key...");
            foundPath = Get7ZipPathFromSpecificRegistryKey();
            if (!string.IsNullOrEmpty(foundPath))
            {
                LogDebug($"Found 7-Zip via specific registry key: {foundPath}");
                return foundPath;
            }
            LogDebug("Specific 7-Zip registry key not found or path invalid.");

            // 4. Attempt to find in system PATH
            LogDebug($"Attempting to find {SevenZipExecutableName} in system PATH...");
            try
            {
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = SevenZipExecutableName;
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.CreateNoWindow = true;
                    process.StartInfo.Arguments = SevenZipSimpleTestArgument;
                    process.Start();

                    process.WaitForExit(500); // Give a brief time for the process to start/fail

                    // If Win32Exception wasn't thrown, it's likely in PATH
                    LogDebug($"Found {SevenZipExecutableName} in system PATH.");
                    return SevenZipExecutableName; // Return just the name
                }
            }
            catch (System.ComponentModel.Win32Exception) // Specifically catch "File Not Found"
            {
                LogDebug($"{SevenZipExecutableName} not found in system PATH.");
            }
            catch (Exception ex)
            {
                LogWarning($"Error checking PATH for {SevenZipExecutableName}: {ex.Message}");
            }

            return null; // Not found
        }

        /// <summary>
        /// Searches the Windows Uninstall registry keys (HKLM and HKCU, 32/64-bit views) for a 7-Zip installation.
        /// </summary>
        /// <returns>The full path to 7z.exe if found and the file exists; otherwise, null.</returns>
        private static string SearchUninstallRegistryFor7Zip()
        {
            var hivesToSearch = new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser };
            var viewsToSearch = new[] { RegistryView.Registry64, RegistryView.Registry32 };

            foreach (RegistryHive hive in hivesToSearch)
            {
                foreach (RegistryView view in viewsToSearch)
                {
                    // Skip searching 64-bit view on 32-bit OS
                    if (view == RegistryView.Registry64 && !Environment.Is64BitOperatingSystem) continue;

                    RegistryKey baseKey = null;
                    RegistryKey uninstallRootKey = null;

                    try
                    {
                        baseKey = RegistryKey.OpenBaseKey(hive, view);
                        // Open read-only for safety
                        uninstallRootKey = baseKey.OpenSubKey(UninstallRegistryPath, writable: false);
                        if (uninstallRootKey == null) continue;

                        // Iterate through applications listed in Uninstall
                        foreach (string appSubKeyName in uninstallRootKey.GetSubKeyNames())
                        {
                            RegistryKey applicationKey = null;
                            try
                            {
                                applicationKey = uninstallRootKey.OpenSubKey(appSubKeyName, writable: false);
                                if (applicationKey == null) continue;

                                string displayName = applicationKey.GetValue("DisplayName") as string;
                                string displayVersion = applicationKey.GetValue("DisplayVersion") as string ?? "";

                                // Case-insensitive check for "7-Zip"
                                if (!string.IsNullOrEmpty(displayName) && displayName.IndexOf("7-Zip", StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    LogDebug($"Found potential match: {displayName} {displayVersion} (Hive: {hive}, View: {view})");

                                    // Strategy 1: Check InstallLocation value
                                    string installLocation = applicationKey.GetValue("InstallLocation") as string;
                                    if (!string.IsNullOrEmpty(installLocation))
                                    {
                                        string potentialPath = Path.Combine(installLocation, SevenZipExecutableName);
                                        if (File.Exists(potentialPath))
                                        {
                                            LogDebug($"  Found executable via InstallLocation: {potentialPath}");
                                            return potentialPath; // Found it!
                                        }
                                        LogDebug($"  InstallLocation found ('{installLocation}'), but {SevenZipExecutableName} not present there.");
                                    }

                                    // Strategy 2: Check DisplayIcon value (often contains path)
                                    string displayIconPath = applicationKey.GetValue("DisplayIcon") as string;
                                    if (!string.IsNullOrEmpty(displayIconPath))
                                    {
                                        // Clean up path (remove quotes, icon index)
                                        string executablePathFromIcon = displayIconPath.Split(',')[0].Trim('"');

                                        // Check if icon path is directly 7z.exe
                                        if (executablePathFromIcon.EndsWith(SevenZipExecutableName, StringComparison.OrdinalIgnoreCase) && File.Exists(executablePathFromIcon))
                                        {
                                            LogDebug($"  Found executable via DisplayIcon (direct path): {executablePathFromIcon}");
                                            return executablePathFromIcon; // Found it!
                                        }
                                        // Check if icon path is another file in the install dir
                                        else if (File.Exists(executablePathFromIcon))
                                        {
                                            string directoryPath = Path.GetDirectoryName(executablePathFromIcon);
                                            if (!string.IsNullOrEmpty(directoryPath))
                                            {
                                                string potentialPath = Path.Combine(directoryPath, SevenZipExecutableName);
                                                if (File.Exists(potentialPath))
                                                {
                                                    LogDebug($"  Found executable via DisplayIcon (derived path): {potentialPath}");
                                                    return potentialPath; // Found it!
                                                }
                                            }
                                            LogDebug($"  DisplayIcon found ('{displayIconPath}'), but could not derive {SevenZipExecutableName} path from it.");
                                        }
                                        else
                                        {
                                            LogDebug($"  DisplayIcon path ('{executablePathFromIcon}') does not exist.");
                                        }
                                    }
                                    LogDebug("  Could not determine executable path from this registry entry.");
                                }
                            }
                            catch (Exception ex)
                            {
                                LogWarning($"Error reading registry subkey '{appSubKeyName}': {ex.Message}");
                            }
                            finally
                            {
                                applicationKey?.Dispose();
                            }
                        }
                    }
                    catch (System.Security.SecurityException)
                    {
                        LogDebug($"Insufficient permissions to read registry. Hive: {hive}, View: {view}.");
                    }
                    catch (Exception ex)
                    {
                        LogWarning($"An error occurred accessing registry. Hive: {hive}, View: {view}. {ex.Message}");
                    }
                    finally
                    {
                        uninstallRootKey?.Dispose();
                        baseKey?.Dispose();
                    }
                }
            }

            // Not found
            return null;
        }

        /// <summary>
        /// Searches the specific 7-Zip registry key (SOFTWARE\7-Zip) in HKLM (32/64-bit views).
        /// </summary>
        /// <returns>The full path to 7z.exe if the key, value, and file exist; otherwise, null.</returns>
        private static string Get7ZipPathFromSpecificRegistryKey()
        {
            RegistryKey baseKey = null;
            RegistryKey sevenZipRegKey = null;

            try
            {
                // Check standard HKLM\SOFTWARE\7-Zip (covers 64-on-64 / 32-on-32)
                baseKey = Registry.LocalMachine.OpenSubKey(SevenZipSpecificRegistryPath, writable: false);

                if (baseKey != null)
                {
                    string installPath = baseKey.GetValue("Path") as string;

                    if (!string.IsNullOrEmpty(installPath))
                    {
                        string potentialPath = Path.Combine(installPath, SevenZipExecutableName);

                        // Found it!
                        if (File.Exists(potentialPath)) return potentialPath;
                    }
                }

                baseKey?.Dispose(); // Dispose before potentially reopening

                // Check HKLM\SOFTWARE\Wow6432Node\7-Zip (for 32-bit on 64-bit OS)
                if (Environment.Is64BitOperatingSystem)
                {
                    // Open 32-bit view of HKLM
                    baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
                    sevenZipRegKey = baseKey.OpenSubKey(SevenZipSpecificRegistryPath, writable: false);

                    if (sevenZipRegKey != null)
                    {
                        string installPath = sevenZipRegKey.GetValue("Path") as string;

                        if (!string.IsNullOrEmpty(installPath))
                        {
                            string potentialPath = Path.Combine(installPath, SevenZipExecutableName);

                            // Found it!
                            if (File.Exists(potentialPath)) return potentialPath;
                        }
                    }
                }
            }
            catch (System.Security.SecurityException)
            {
                LogDebug($"Insufficient permissions to read specific 7-Zip registry key.");
            }
            catch (Exception ex)
            {
                LogWarning($"Error reading specific 7-Zip registry key: {ex.Message}");
            }
            finally
            {
                sevenZipRegKey?.Dispose();
                baseKey?.Dispose();
            }

            // Not found
            return null;
        }
    }
}