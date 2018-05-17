using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace DigiByteNet
{
    public class Message
    {
        private byte[] MAGIC_BYTES = Encoding.UTF8.GetBytes("DigiByte Signed Message:\n");
        
        public string Text { get; set; }

        public Message(string text)
        {
            this.Text = text;
        }

        public byte[] MagicHash()
        {
            using (var str = new MemoryStream())
            {
                byte[] buff;
                buff = Helpers.GetNumberBytes(this.MAGIC_BYTES.LongLength);
                str.Write(buff, 0, buff.Length);
                str.Write(MAGIC_BYTES, 0, this.MAGIC_BYTES.Length);

                buff = Helpers.GetNumberBytes(this.Text.ToCharArray().LongLength);
                str.Write(buff, 0, buff.Length);

                buff = Encoding.UTF8.GetBytes(this.Text);
                str.Write(buff, 0, buff.Length);

                using (var sha256 = new SHA256Managed())
                {
                    buff = str.ToArray();
                    buff = sha256.ComputeHash(buff, 0, buff.Length);
                    return sha256.ComputeHash(buff, 0, buff.Length);
                }
            }

        }

        public Signature Sign(PrivateKey priv)
        {
            var data = this.MagicHash();

            var signer = new DgbECDsaSigner();
            signer.Init(true, new ECPrivateKeyParameters(priv.BN, Config.ECDomain), true);

            var signatureData = signer.GenerateSignature(data);
            return new Signature(signatureData[0], signatureData[1], data, priv.ToPublicKey());
        }

        public bool Verify(string addressString, string signatureString)
        {
            var data = this.MagicHash();
            var signature = Signature.FromCompact(Convert.FromBase64String(signatureString));
            signature.Data = data;

            var address = Address.FromString(addressString);
            var signatureAddress = Address.FromPublicKey(signature.GetPublicKey());

            if (signatureAddress.ToString() != addressString)
            {
                return false;
            }

            var signer = new DgbECDsaSigner();
            signer.Init(false, new ECPublicKeyParameters(signature.GetPublicKey().Point, Config.ECDomain));
            return signer.VerifySignature(this.MagicHash(), signature.R, signature.S);
        }

    }
}
