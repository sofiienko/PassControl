using System;
using System.Collections.Generic;
using System.Data;
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
using System.Windows.Shapes;

namespace PassControl
{
    /// <summary>
    /// Логика взаимодействия для Window1.xaml
    /// </summary>
    public partial class TableWindows : Window
    {
        public TableWindows()
        {
            InitializeComponent();
        }
        public TableWindows(DataTable dataTable)
        {
            InitializeComponent();
            gridFile.ItemsSource = dataTable.DefaultView;
        }
    }
}
