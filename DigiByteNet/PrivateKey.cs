using Base58Check;
using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;


namespace DigiByteNet
{
    public class PrivateKey
    {
        private PublicKey _pub;

        public BigInteger BN { get; }
        public bool Compressed { get; }
        public NetworkItem Network { get; }

        private PrivateKey(BigInteger bn, bool compressed, NetworkItem network)
        {
            this.BN = bn;
            this.Compressed = compressed;
            this.Network = network;
        }

        public PrivateKey() : this(DigiByteNet.Network.LiveNet) { }
        public PrivateKey(NetworkItem network)
        {
            this.Compressed = true;
            this.Network = network;

            var rng = new RNGCryptoServiceProvider();
            byte[] data = new byte[32];
            do
            {
                rng.GetBytes(data);
                this.BN = new BigInteger(1, data);
            }
            while (this.BN.CompareTo(Config.Curve.N) >= 0);
        }

        public string ToWif()
        {
            var priv = this.BN.ToByteArray();
            byte[] res;

            if (this.Compressed)
            {
                res = new byte[34];
                res[res.Length - 1] = 0x01;
            }
            else
            {
                res = new byte[33];
            }

            Array.Copy(priv, 0, res, 1, priv.Length);

            res[0] = this.Network.PrivKeyPrefix;

            return Base58CheckEncoding.Encode(res);
        }

        public PublicKey ToPublicKey()
        {
            if (this._pub == null)
            {
                this._pub = PublicKey.FromPrivateKey(this);
            }

            return this._pub;
        }

        public static PrivateKey FromWif(string base58)
        {
            var data = Base58CheckEncoding.Decode(base58);
            bool compressed;

            var network = DigiByteNet.Network.GetFromPrivKeyPrefix(data[0]);
            if (network == null)
            {
                throw new ArgumentException("Invalid Network!");
            }

            if (data.Length == 1 + 32 + 1 && data[data.Length - 1] == 0x01)
            {
                compressed = true;
            }
            else if (data.Length == 1 + 32)
            {
                compressed = false;
            }
            else
            {
                throw new ArgumentException("Invalid WIF format!");
            }

            return new PrivateKey(new BigInteger(data, 1, 32), compressed, network.Value);
        }
    }
}
