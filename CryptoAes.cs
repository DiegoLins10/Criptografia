using Interface.Cryptographc;
using Domain.Models.Commons;
using Microsoft.Extensions.Options;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Application.Cryptographic
{
    public class CryptoAes : ICryptoAes
    {
        private readonly CryptoAesConfig _cryptoAesConfig;

        private AesManaged _aes { get; set; }

        public AesManaged Aes
        {
            get
            {
                if (_aes == null)
                {
                    _aes = CreateAes();
                }

                return _aes;
            }
        }

        public CryptoAes(IOptionsMonitor<ApiSettings> apiSettings)
        {
            _cryptoAesConfig = apiSettings?.CurrentValue.CryptoAesConfig;
        }

        private AesManaged CreateAes()
        {
            AesManaged aesAlg = new();
            aesAlg.Key = Encoding.UTF8.GetBytes(_cryptoAesConfig.Key);
            aesAlg.IV = Encoding.UTF8.GetBytes(_cryptoAesConfig.Vector);

            return aesAlg;
        }

        public string EncryptStringToBytesAes(string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return text;
            }

            ICryptoTransform encryptor = Aes.CreateEncryptor();

            using MemoryStream ms = new();
            using CryptoStream cs = new(ms, encryptor, CryptoStreamMode.Write);
            using (StreamWriter sw = new(cs))
                sw.Write(text);

            var encrypted = Convert.ToBase64String(ms.ToArray());
         
            return encrypted;
        }

        public string Decrypt(string text)
        {
            using var aes = CreateAes();
            ICryptoTransform decryptor = aes.CreateDecryptor();
            using MemoryStream ms = new MemoryStream(Convert.FromBase64String(text));
            using CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
            using StreamReader reader = new StreamReader(cs);
            return reader.ReadToEnd();
        }
    }
}
