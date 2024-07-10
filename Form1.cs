using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace UnpackMiniApp
{
    public partial class Form1 : Form
    {
        private string AppletPath = null;
        private string AppPath = null;
        private string outFileName = "";

        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            this.labelUsage.Text = "使用说明：选择小程序包进行解密，自动判断是否需要解密";
            this.tbxLog.Text= "解密后放在wxpack文件夹，请勿删除该文件夹";
            this.AppletPath = Environment.GetFolderPath(Environment.SpecialFolder.Personal) + "\\WeChat Files\\Applet\\";
            this.AppPath = Directory.GetCurrentDirectory();
        }

        public static byte[] AESDecrypt(byte[] inputdata, byte[] iv, byte[] strKey)
        {
            SymmetricAlgorithm symmetricAlgorithm = Rijndael.Create();
            symmetricAlgorithm.Key = strKey;
            symmetricAlgorithm.IV = iv;
            byte[] array = new byte[inputdata.Length];
            using (MemoryStream memoryStream = new MemoryStream(inputdata))
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, symmetricAlgorithm.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    cryptoStream.Read(array, 0, array.Length);
                    cryptoStream.Close();
                    memoryStream.Close();
                }
            }
            return array;
        }

        private static int Asc(string s)
        {
            bool flag = s.Length == 1;
            if (flag)
            {
                ASCIIEncoding asciiencoding = new ASCIIEncoding();
                return (int)asciiencoding.GetBytes(s)[0];
            }
            throw new Exception("String is not vaild");
        }

        private byte[] FileContent(string fileName)
        {
            byte[] array2;
            using (FileStream fileStream = new FileStream(fileName, FileMode.Open, FileAccess.Read))
            {
                try
                {
                    byte[] array = new byte[fileStream.Length];
                    fileStream.Read(array, 0, (int)fileStream.Length);
                    array2 = array;
                }
                catch (Exception ex)
                {
                    throw ex;
                }
            }
            return array2;
        }

        private string GetStr(string TxtStr, string FirstStr, string SecondStr)
        {
            string[] array = Regex.Split(TxtStr, FirstStr, RegexOptions.IgnoreCase);
            bool flag = array.Length < 2;
            string text;
            if (flag)
            {
                text = "";
            }
            else
            {
                string[] array2 = Regex.Split(array[1], SecondStr, RegexOptions.IgnoreCase);
                text = array2[0];
            }
            return text;
        }

        public string GetTimeStamp()
        {
            return Convert.ToInt64((DateTime.Now - new DateTime(1970, 1, 1, 0, 0, 0, 0)).TotalSeconds).ToString();
        }

        public byte[] PBKDF2(string wxid, string salts)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(salts);
            Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(wxid, bytes, 1000);
            return rfc2898DeriveBytes.GetBytes(32);
        }

        protected void writerFile(byte[] array, string fileName)
        {
            FileStream fileStream = new FileStream(fileName, FileMode.Create);
            fileStream.Write(array, 0, array.Length);
            fileStream.Close();
        }

        private void doUnpack_Click(object sender, EventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.InitialDirectory = this.AppletPath;
            DialogResult dialogResult = openFileDialog.ShowDialog();
            this.tbxLog.Text = "";
            bool flag = dialogResult == DialogResult.OK;
            if (flag)
            {
                string fileName = openFileDialog.FileName;
                byte[] array = this.FileContent(fileName);
                string @string = Encoding.UTF8.GetString(array.Take(6).ToArray<byte>());
                this.tbxLog.AppendText("文件选择：" + fileName + "\r\n");
                bool flag2 = @string == "V1MMWX";
                if (flag2)
                {
                    string str = this.GetStr(fileName, "Applet\\\\", "\\\\");
                    bool flag3 = str == "";
                    if (flag3)
                    {
                        this.tbxLog.AppendText("小程序ID获取失败，无法解密！...\r\n");
                    }
                    else
                    {
                        this.outFileName = "\\wxpack\\" + str + ".wxapkg";
                        this.tbxLog.AppendText("文件解密中...\r\n");
                        string text = "saltiest";
                        byte[] bytes = Encoding.UTF8.GetBytes("the iv: 16 bytes");
                        byte[] array2 = this.PBKDF2(str, text);
                        byte[] array3 = Form1.AESDecrypt(array.Skip(6).Take(1024).ToArray<byte>(), bytes, array2);
                        byte[] array4 = array.Skip(6).Take(1024).ToArray<byte>();
                        byte[] array5 = array.Skip(1030).ToArray<byte>();
                        int num = Form1.Asc(str.Substring(str.Length - 2, 1));
                        int num2 = array5.Length;
                        List<byte> list = new List<byte>();
                        list.AddRange(array3.Take(1023).ToArray<byte>());
                        int num3;
                        for (int i = 0; i < num2; i = num3 + 1)
                        {
                            list.Add((byte)((int)array5[i] ^ num));
                            num3 = i;
                        }
                        this.tbxLog.AppendText("解密成功->" + this.outFileName + "\r\n");
                        this.writerFile(list.ToArray(), this.AppPath + this.outFileName);
                    }
                }
                else
                {
                    this.tbxLog.AppendText("文件未加密,无需解密...\r\n");
                }
            }
        }
    }
}
