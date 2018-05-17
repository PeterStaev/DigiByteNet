#region License
/*
The MIT License (MIT)

Copyright (c) 2018 Tangra Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#endregion
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
