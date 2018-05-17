using Base58Check;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace DigiByteNet
{
    public class Address
    {
        private readonly byte[] _hash;
        private readonly NetworkItem _network;

        private Address(byte[] hash, NetworkItem network)
        {
            this._hash = hash;
            this._network = network;
        }

        public byte[] ToByteArray()
        {
            using (var str = new MemoryStream())
            {
                str.WriteByte(this._network.PubKeyHash);
                str.Write(this._hash, 0, this._hash.Length);

                return str.ToArray();
            }
        }

        public override string ToString()
        {
            return Base58CheckEncoding.Encode(this.ToByteArray());
        }

        public static Address FromPublicKey(PublicKey pub)
        {
            using (var sha256 = new SHA256Managed())
            {
                var hash = sha256.ComputeHash(pub.ToByteArray());
                using (var ripemid160 = new RIPEMD160Managed())
                {
                    return new Address(ripemid160.ComputeHash(hash), pub.Network);
                }
            }
        }

        public static Address FromString(string address)
        {
            var data = Base58CheckEncoding.Decode(address);
            if (data.Length != 20+1)
            {
                throw new ArgumentException("Invalid address");
            }

            var network = Network.GetFromPubKeyHash(data[0]);
            if (network == null)
            {
                throw new ArgumentException("Unknown address hash");
            }

            return new Address(data.Skip(1).Take(20).ToArray(), network.Value);
        }
    }
}
