using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Data.SQLite;
using System.Data;
using System.IO;
using System.Windows;

namespace PassControl
{
    public class DPAPI
    {
        [DllImport("crypt32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        private static extern
            bool CryptProtectData(ref DATA_BLOB pPlainText, string szDescription, ref DATA_BLOB pEntropy, IntPtr pReserved,
                                             ref CRYPTPROTECT_PROMPTSTRUCT pPrompt, int dwFlags, ref DATA_BLOB pCipherText);

        [DllImport("crypt32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        private static extern
            bool CryptUnprotectData(ref DATA_BLOB pCipherText, ref string pszDescription, ref DATA_BLOB pEntropy,
                  IntPtr pReserved, ref CRYPTPROTECT_PROMPTSTRUCT pPrompt, int dwFlags, ref DATA_BLOB pPlainText);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct CRYPTPROTECT_PROMPTSTRUCT
        {
            public int cbSize;
            public int dwPromptFlags;
            public IntPtr hwndApp;
            public string szPrompt;
        }

        static private IntPtr NullPtr = ((IntPtr)((int)(0)));

        private const int CRYPTPROTECT_UI_FORBIDDEN = 0x1;
        private const int CRYPTPROTECT_LOCAL_MACHINE = 0x4;

        private static void InitPrompt(ref CRYPTPROTECT_PROMPTSTRUCT ps)
        {
            ps.cbSize = Marshal.SizeOf(
                                      typeof(CRYPTPROTECT_PROMPTSTRUCT));
            ps.dwPromptFlags = 0;
            ps.hwndApp = NullPtr;
            ps.szPrompt = null;
        }

        private static void InitBLOB(byte[] data, ref DATA_BLOB blob)
        {
            // Use empty array for null parameter.
            if (data == null)
                data = new byte[0];

            // Allocate memory for the BLOB data.
            blob.pbData = Marshal.AllocHGlobal(data.Length);

            // Make sure that memory allocation was successful.
            if (blob.pbData == IntPtr.Zero)
                throw new Exception(
                    "Unable to allocate data buffer for BLOB structure.");

            // Specify number of bytes in the BLOB.
            blob.cbData = data.Length;

            // Copy data from original source to the BLOB structure.
            Marshal.Copy(data, 0, blob.pbData, data.Length);
        }

        public enum KeyType { UserKey = 1, MachineKey };

        private static KeyType defaultKeyType = KeyType.UserKey;

        public static string Encrypt(string plainText)
        {
            return Encrypt(defaultKeyType, plainText, String.Empty, String.Empty);
        }

        public static string Encrypt(KeyType keyType, string plainText)
        {
            return Encrypt(keyType, plainText, String.Empty,
                            String.Empty);
        }

        public static string Encrypt(KeyType keyType, string plainText, string entropy)
        {
            return Encrypt(keyType, plainText, entropy, String.Empty);
        }

        public static string Encrypt(KeyType keyType, string plainText, string entropy, string description)
        {
            // Make sure that parameters are valid.
            if (plainText == null) plainText = String.Empty;
            if (entropy == null) entropy = String.Empty;

            // Call encryption routine and convert returned bytes into
            // a base64-encoded value.
            return Convert.ToBase64String(
                    Encrypt(keyType,
                            Encoding.UTF8.GetBytes(plainText),
                            Encoding.UTF8.GetBytes(entropy),
                            description));
        }

        public static byte[] Encrypt(KeyType keyType, byte[] plainTextBytes, byte[] entropyBytes, string description)
        {
            // Make sure that parameters are valid.
            if (plainTextBytes == null) plainTextBytes = new byte[0];
            if (entropyBytes == null) entropyBytes = new byte[0];
            if (description == null) description = String.Empty;

            // Create BLOBs to hold data.
            DATA_BLOB plainTextBlob = new DATA_BLOB();
            DATA_BLOB cipherTextBlob = new DATA_BLOB();
            DATA_BLOB entropyBlob = new DATA_BLOB();

            // We only need prompt structure because it is a required
            // parameter.
            CRYPTPROTECT_PROMPTSTRUCT prompt =
                                      new CRYPTPROTECT_PROMPTSTRUCT();
            InitPrompt(ref prompt);

            try
            {
                // Convert plaintext bytes into a BLOB structure.
                try
                {
                    InitBLOB(plainTextBytes, ref plainTextBlob);
                }
                catch (Exception ex)
                {
                    throw new Exception(
                        "Cannot initialize plaintext BLOB.", ex);
                }

                // Convert entropy bytes into a BLOB structure.
                try
                {
                    InitBLOB(entropyBytes, ref entropyBlob);
                }
                catch (Exception ex)
                {
                    throw new Exception(
                        "Cannot initialize entropy BLOB.", ex);
                }

                // Disable any types of UI.
                int flags = CRYPTPROTECT_UI_FORBIDDEN;

                // When using machine-specific key, set up machine flag.
                if (keyType == KeyType.MachineKey)
                    flags |= CRYPTPROTECT_LOCAL_MACHINE;

                // Call DPAPI to encrypt data.
                bool success = CryptProtectData(ref plainTextBlob,
                                                    description,
                                                ref entropyBlob,
                                                    IntPtr.Zero,
                                                ref prompt,
                                                    flags,
                                                ref cipherTextBlob);
                // Check the result.
                if (!success)
                {
                    // If operation failed, retrieve last Win32 error.
                    int errCode = Marshal.GetLastWin32Error();

                    // Win32Exception will contain error message corresponding
                    // to the Windows error code.
                    throw new Exception(
                        "CryptProtectData failed.", new Win32Exception(errCode));
                }

                // Allocate memory to hold ciphertext.
                byte[] cipherTextBytes = new byte[cipherTextBlob.cbData];

                // Copy ciphertext from the BLOB to a byte array.
                Marshal.Copy(cipherTextBlob.pbData,
                                cipherTextBytes,
                                0,
                                cipherTextBlob.cbData);

                // Return the result.
                return cipherTextBytes;
            }
            catch (Exception ex)
            {
                throw new Exception("DPAPI was unable to encrypt data.", ex);
            }
            // Free all memory allocated for BLOBs.
            finally
            {
                if (plainTextBlob.pbData != IntPtr.Zero)
                    Marshal.FreeHGlobal(plainTextBlob.pbData);

                if (cipherTextBlob.pbData != IntPtr.Zero)
                    Marshal.FreeHGlobal(cipherTextBlob.pbData);

                if (entropyBlob.pbData != IntPtr.Zero)
                    Marshal.FreeHGlobal(entropyBlob.pbData);
            }
        }

        public static string Decrypt(string cipherText)
        {
            string description;

            return Decrypt(cipherText, String.Empty, out description);
        }

        public static string Decrypt(string cipherText, out string description)
        {
            return Decrypt(cipherText, String.Empty, out description);
        }

        public static string Decrypt(string cipherText, string entropy, out string description)
        {
            // Make sure that parameters are valid.
            if (entropy == null) entropy = String.Empty;

            return Encoding.UTF8.GetString(
                        Decrypt(Convert.FromBase64String(cipherText),
                                    Encoding.UTF8.GetBytes(entropy),
                                out description));
        }

        public static byte[] Decrypt(byte[] cipherTextBytes, byte[] entropyBytes, out string description)
        {
            // Create BLOBs to hold data.
            DATA_BLOB plainTextBlob = new DATA_BLOB();
            DATA_BLOB cipherTextBlob = new DATA_BLOB();
            DATA_BLOB entropyBlob = new DATA_BLOB();

            // We only need prompt structure because it is a required
            // parameter.
            CRYPTPROTECT_PROMPTSTRUCT prompt =
                                      new CRYPTPROTECT_PROMPTSTRUCT();
            InitPrompt(ref prompt);

            // Initialize description string.
            description = String.Empty;

            try
            {
                // Convert ciphertext bytes into a BLOB structure.
                try
                {
                    InitBLOB(cipherTextBytes, ref cipherTextBlob);
                }
                catch (Exception ex)
                {
                    throw new Exception(
                        "Cannot initialize ciphertext BLOB.", ex);
                }

                // Convert entropy bytes into a BLOB structure.
                try
                {
                    InitBLOB(entropyBytes, ref entropyBlob);
                }
                catch (Exception ex)
                {
                    throw new Exception(
                        "Cannot initialize entropy BLOB.", ex);
                }

                // Disable any types of UI. CryptUnprotectData does not
                // mention CRYPTPROTECT_LOCAL_MACHINE flag in the list of
                // supported flags so we will not set it up.
                int flags = CRYPTPROTECT_UI_FORBIDDEN;

                // Call DPAPI to decrypt data.
                bool success = CryptUnprotectData(ref cipherTextBlob,
                                                  ref description,
                                                  ref entropyBlob,
                                                      IntPtr.Zero,
                                                  ref prompt,
                                                      flags,
                                                  ref plainTextBlob);

                // Check the result.
                if (!success)
                {
                    // If operation failed, retrieve last Win32 error.
                    int errCode = Marshal.GetLastWin32Error();

                    // Win32Exception will contain error message corresponding
                    // to the Windows error code.
                    throw new Exception(
                        "CryptUnprotectData failed.", new Win32Exception(errCode));
                }

                // Allocate memory to hold plaintext.
                byte[] plainTextBytes = new byte[plainTextBlob.cbData];

                // Copy ciphertext from the BLOB to a byte array.
                Marshal.Copy(plainTextBlob.pbData,
                             plainTextBytes,
                             0,
                             plainTextBlob.cbData);

                // Return the result.
                return plainTextBytes;
            }
            catch (Exception ex)
            {
                throw new Exception("DPAPI was unable to decrypt data.", ex);
            }
            // Free all memory allocated for BLOBs.
            finally
            {
                if (plainTextBlob.pbData != IntPtr.Zero)
                    Marshal.FreeHGlobal(plainTextBlob.pbData);

                if (cipherTextBlob.pbData != IntPtr.Zero)
                    Marshal.FreeHGlobal(cipherTextBlob.pbData);

                if (entropyBlob.pbData != IntPtr.Zero)
                    Marshal.FreeHGlobal(entropyBlob.pbData);
            }
        }
    }

        static   class IsFileLocked
        {
             public static bool Check(FileInfo file)
             {
                FileStream stream = null;

                try
                {
                    stream = file.Open(FileMode.Open, FileAccess.Read, FileShare.None);
                }
                catch (IOException)
                {
                    //the file is unavailable because it is:
                    //still being written to
                    //or being processed by another thread
                    //or does not exist (has already been processed)
                    return true;
                }
                finally
                {
                    if (stream != null)
                        stream.Close();
                }

                //file is not locked
                return false;
            }
        }

    public static class BrowserSecret
    {
        public enum Browser { Opera, Chrome };
        public enum TypeFile { LoginData, Cookies };
        public enum Process { Encrypt, Decrypt };




        public static void DecryptAndUpdateFile(string filePath, string cryptedTable, params string[] cryptedField)
        {
            if (!File.Exists(filePath))
                throw new Exception("file " + filePath + " not found");

            if (IsFileLocked.Check(new FileInfo(filePath)))
                throw new Exception("File is locked. Please close browser");


            string connectionString = "data source=" + filePath + ";New=True;UseUTF8Encoding=True";
            DataTable table = new DataTable();

            string query = string.Format("SELECT * FROM {0} ", cryptedTable);

            using (SQLiteConnection connect = new SQLiteConnection(connectionString))
            {
                SQLiteCommand command = new SQLiteCommand(query, connect);
                SQLiteDataAdapter adapter = new SQLiteDataAdapter(command);

                connect.Open();
                adapter.Fill(table);
                string description;
                byte[] entropy = null;

                int[] cryptFiled = new int[cryptedField.Length];
                for (int i = 0; i < cryptedField.Length; i++)
                    cryptFiled[i] = table.Columns.IndexOf(cryptedField[i]);

              
                for (int i = 0; i < table.Rows.Count; i++)
                {
                    for (int j = 0; j < cryptFiled.Length; j++)
                    {
                        byte[] array = (byte[])table.Rows[i][cryptFiled[j]];

                        byte[] decript = DPAPI.Decrypt(array, entropy, out description);
                        //table.Rows[i][cryptFiled[j]] = decript ?? throw new Exception("all very bad");
                        //adapter.UpdateCommand = new SQLiteCommand("UPDATE " + cryptedTable + " SET password_value = @password_value WHERE origin_url=@origin_url ", adapter.SelectCommand.Connection);
                        //var updateParametrs = adapter.UpdateCommand.Parameters;
                        //updateParametrs.Add("@password_value", DbType.Binary,decript.Length);
                        //updateParametrs["@password_value"].Value = decript;
                        //updateParametrs.Add("@origin_url", DbType.String, 25, "origin_url");
                        //adapter.Update(table);

                        SQLiteCommand cmd = new SQLiteCommand(connect);
                        cmd.CommandText = "UPDATE " + cryptedTable + " SET password_value = @password_value WHERE origin_url=@origin_url ";
                        cmd.Prepare();
                        cmd.Parameters.Add("@password_value", DbType.Binary, decript.Length);
                        cmd.Parameters["@password_value"].Value = decript;
                        cmd.Parameters.Add("@origin_url", DbType.String, 25, "origin_url");
                        cmd.Parameters["@origin_url"].Value = table.Rows[i][0];
                        cmd.ExecuteNonQuery();

                        //SQLiteCommand cmd2 = new SQLiteCommand(connect);
                        //cmd2.CommandText = "SELECT Data FROM Images WHERE Id="+;
                        //byte[] data = (byte[])cmd.ExecuteScalar();
                    }
                }
                connect.Close();
                //MessageBox.Show(parsedPass);
                //if (cryptedTable == "logins")
                //{
                //    //adapter.UpdateCommand = new SQLiteCommand("UPDATE " + cryptedTable + " SET password_value = @password_value WHERE origin_url=@origin_url ", adapter.SelectCommand.Connection);
                //    //var updateParametrs = adapter.UpdateCommand.Parameters;
                //    //updateParametrs.Add("@password_value", DbType.Binary);
                //    //updateParametrs.Add("@origin_url", DbType.String,25, "origin_url");
                //    //adapter.Update(table);
                //    int i = 0;
                //    int index = table.Columns.IndexOf("password_value");
                //    MessageBox.Show(((byte[])table.Rows[0][index]).Length.ToString());

                //    while (i<table.Rows.Count)
                //    {
                //        adapter.UpdateCommand = new SQLiteCommand("UPDATE " + cryptedTable + " SET password_value = @password_value WHERE origin_url=@origin_url ", adapter.SelectCommand.Connection);
                //        var updateParametrs = adapter.UpdateCommand.Parameters;
                //        updateParametrs.AddWithValue("@password_value", table.Rows[i][index]);
                //        updateParametrs.Add("@origin_url", DbType.String, 25, "origin_url");
                //        adapter.Update(table);

                //        i++;
                //    };


                //}
                //else if (cryptedTable == "cookies")
                //{
                //    adapter.UpdateCommand = new SQLiteCommand("UPDATE " + cryptedTable + " SET encrypted_value = @encrypted_value", adapter.SelectCommand.Connection);
                //    var updateParametrs = adapter.UpdateCommand.Parameters;
                //    updateParametrs.Add("@encrypted_value", DbType.Binary);
                //    adapter.Update(table);
                //}

            }

        }

        public static  DataTable DecryptFile(Process typeProces, string filePath, string cryptedTable, params string[] cryptedField)
        {
            if (!File.Exists(filePath)) throw new Exception("file " + filePath + " not found");

            string connectionString = "data source=" + filePath + ";New=True;UseUTF16Encoding=True";
            DataTable table = new DataTable();

            string query = string.Format("SELECT * FROM {0} ", cryptedTable);

            using (SQLiteConnection connect = new SQLiteConnection(connectionString))
            {
                SQLiteCommand command = new SQLiteCommand(query, connect);
                SQLiteDataAdapter adapter = new SQLiteDataAdapter(command);

                adapter.Fill(table);
                string description;
                byte[] entropy = null;

                int[] cryptFiled = new int[cryptedField.Length];
                for (int i = 0; i < cryptedField.Length; i++)
                    cryptFiled[i] = table.Columns.IndexOf(cryptedField[i]);


                for (int i = 0; i < table.Rows.Count; i++)
                {
                    for (int j = 0; j < cryptFiled.Length; j++)
                    {
                        byte[] array = (byte[])table.Rows[i][cryptFiled[j]];
                        byte[] decript = typeProces == Process.Decrypt ? DPAPI.Decrypt(array, entropy, out description)
                            : DPAPI.Encrypt(DPAPI.KeyType.MachineKey, array, entropy, null);
                        table.Rows[i][cryptFiled[j]] = decript;
                    }
                }
            }
            return table;
        }



        public static void DecryptAndUpdateFile(string filePath, TypeFile typefile)
        {
            if (typefile == TypeFile.LoginData)
                DecryptAndUpdateFile(filePath, "logins", "password_value"/*, "form_data", "possible_username_pairs"*/);

            else if (typefile == TypeFile.Cookies)
                DecryptAndUpdateFile(filePath, "cookies", "encrypted_value");
        }



        public static void Encrypt(string filePath, string cryptedTable, string cryptedField)
        {
            string connectionString = "data source=" + filePath + ";New=True;UseUTF16Encoding=True";
            DataTable table = new DataTable();

            string query = string.Format("SELECT * FROM {0} {1} {2}", cryptedTable, "", "");

            using (SQLiteConnection connect = new SQLiteConnection(connectionString))
            {
                SQLiteCommand command = new SQLiteCommand(query, connect);
                SQLiteDataAdapter adapter = new SQLiteDataAdapter(command);

                adapter.Fill(table);

                int cryptFiled = table.Columns.IndexOf(cryptedField);

                for (int i = 0; i < table.Rows.Count; i++)
                {
                    byte[] array = (byte[])table.Rows[i][cryptFiled];
                    byte[] encrypt = DPAPI.Encrypt(DPAPI.KeyType.UserKey, array, null, null);

                    table.Rows[i][cryptFiled] = encrypt;
                }
                adapter.Update(table);
            }

        }
        public static void EncryptFile(Browser browser, TypeFile filetype)
        {

        }
    }
}
