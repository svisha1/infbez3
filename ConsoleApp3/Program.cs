using System.Security.Cryptography;
using System.Text;

namespace ConsoleApp3
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] signaturebytes;
            DSAParameters dsaparams;

            string file_name = Console.ReadLine();
            StreamReader reader = new StreamReader(file_name);
            string fileForDSA = reader.ReadToEnd();
            reader.Close();

            //Подписание сообщения
            byte[] messagebytes = Encoding.UTF8.GetBytes(fileForDSA);//файл

            //создание дайджеста сообщения по алгориму SHA1
            SHA1 sha1 = new SHA1CryptoServiceProvider();
            byte[] hashbytes = sha1.ComputeHash(messagebytes);//хеширование файла

            //создание объекта DSA с ключом по умолчанию
            DSACryptoServiceProvider dsa = new DSACryptoServiceProvider();
            signaturebytes = dsa.SignHash(hashbytes,"1.3.14.3.2.26");//создание эцп для заданного файла
            dsaparams = dsa.ExportParameters(false);

            string file_name2 = Console.ReadLine();
            StreamWriter writer = new StreamWriter(file_name2);
            writer.Write("Hash data: {0}", Encoding.UTF8.GetString(signaturebytes));
            writer.Close();

            //создание объекта DSA с импортированными параметрами
            dsa.ImportParameters(dsaparams);
            StreamReader reader2 = new StreamReader(file_name);
            fileForDSA = reader2.ReadToEnd();
            reader2.Close();
            messagebytes = Encoding.UTF8.GetBytes(fileForDSA);
            hashbytes = sha1.ComputeHash(messagebytes);
            //StreamReader reader3 = new StreamReader(file_name2);
            //signaturebytes = Encoding.UTF8.GetBytes(reader3.ReadToEnd());
            //reader3.Close();
            bool match = dsa.VerifyHash(hashbytes, "1.3.14.3.2.26", signaturebytes);
            Console.WriteLine(match);
        }
    }
}