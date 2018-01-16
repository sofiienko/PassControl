using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace PassControl
{
    /// <summary>
    /// Логика взаимодействия для MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            

            if (!Directory.Exists("specialFolder"))
            {
                Directory.CreateDirectory("specialFolder");
            }

            GridInitialization();
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {

        }


        #region Buttom_Press
        private void copyOperaLogin(object sender, RoutedEventArgs e)
        {
            CopyFile(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
              + "/Opera Software/Opera Stable/Login Data");
        }

        private void copyChromeLogin(object sender, RoutedEventArgs e)
        {
            CopyFile(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
            + "/Google/Chrome/User Data/Default/Login Data");

        }

        private void copyOperaCookies(object sender, RoutedEventArgs e)
        {
            CopyFile(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
              + "/Opera Software/Opera Stable/Cookies");
            
        }

        private void copyChromeCookies(object sender, RoutedEventArgs e)
        {
            CopyFile(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
            + "/Google/Chrome/User Data/Default/Cookies");

        }

        private void CopyFile(string path)
        {

            FileInfo file = new FileInfo(path);
            if (file.Exists)
            {
                StringBuilder newPath = new StringBuilder();
                newPath.Append("specialFolder/" + file.Name + "_" + Environment.UserName);

                if (path.Contains("Chrome")) newPath.Append("_Chrome_");
                else newPath.Append("_Opera_");

                BrowserSecret.TypeFile tipeFile = BrowserSecret.TypeFile.LoginData;
                if (path.Contains("Cookies")) tipeFile = BrowserSecret.TypeFile.Cookies;
                

                newPath.Append(Environment.UserName);
                if (!File.Exists(newPath.ToString()))
                {
                    file.CopyTo(newPath.ToString());
                    BrowserSecret.DecryptAndUpdateFile(newPath.ToString(), tipeFile);
                }
                else
                {
                    var result = MessageBox.Show("File alreade exist", "Question",
                                                 MessageBoxButton.YesNo);

                    if (result == MessageBoxResult.Yes)
                    {
                        FileInfo temp = new FileInfo(newPath.ToString());
                        temp.Delete();
                        file.CopyTo(newPath.ToString());
                        BrowserSecret.DecryptAndUpdateFile(newPath.ToString(), tipeFile);

                    }

                }

            }
            
        }
        #endregion

        void GridInitialization()
        {
            DirectoryInfo info = new DirectoryInfo("specialFolder");
            
            gridFile.ItemsSource = info.GetFiles();
       
        }


        void ShowDecryptedTable(object sender, RoutedEventArgs e)
        {
            MenuItem menuItem = sender as MenuItem;
            ContextMenu contextMenu = (ContextMenu)menuItem.Parent;
            DataGrid item = (DataGrid)contextMenu.PlacementTarget;
            //  var toDeleteFromBindedList = item.SelectedCells[0].Item;
            FileInfo selectedFile = (FileInfo)item.SelectedItem;
            MessageBox.Show(selectedFile.ToString());






            string connectionString = "data source=" + selectedFile.FullName + ";New=True;UseUTF8Encoding=True";
            DataTable table = new DataTable();

            string cryptedTable;
            string cryptedField;

            if ((selectedFile.ToString().Contains("Login Data")))
            {
                cryptedTable = "logins";
                cryptedField = "password_value";
            }
            else if ((selectedFile.ToString().Contains("Cookies")))
            {
                cryptedTable = "cookies";
                cryptedField = "encrypted_value";
            }
            else
            {
                cryptedTable = "cookies";
                cryptedField = "encrypted_value";
            }



            string query = string.Format("SELECT * FROM {0} ", cryptedTable);

            using (SQLiteConnection connect = new SQLiteConnection(connectionString))
            {
                SQLiteCommand command = new SQLiteCommand(query, connect);
                SQLiteDataAdapter adapter = new SQLiteDataAdapter(command);

                adapter.Fill(table);


                table.Columns.Add(cryptedField + "2", typeof(String));

                int byteFiled = table.Columns.IndexOf(cryptedField);
                int stringFiled = table.Columns.IndexOf(cryptedField+"2");

                for (int i = 0; i < table.Rows.Count; i++)
                {
                    byte[] array = (byte[])  ( !DBNull.Value.Equals(table.Rows[i][byteFiled])? table.Rows[i][byteFiled] :throw new Exception());
                    table.Rows[i][stringFiled] = new UTF8Encoding(true).GetString(array);
                    MessageBox.Show(new UTF8Encoding(true).GetString(array));
                }

                TableWindows tableWindows = new TableWindows(table);


                tableWindows.Show();



            }
        }
    }
}
