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
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DigiByteNet
{
    public struct NetworkItem
    {
        public NetworkItem(string name, byte privKeyPrefix, byte pubKeyHash)
        {
            this.Name = name;
            this.PrivKeyPrefix = privKeyPrefix;
            this.PubKeyHash = pubKeyHash;
        }

        public readonly string Name;
        public readonly byte PrivKeyPrefix;
        public readonly byte PubKeyHash;
    }

    public static class Network
    {
        public static readonly NetworkItem LiveNet = new NetworkItem("livenet", 0x80, 0x1e);
        public static readonly NetworkItem TestNet = new NetworkItem("testnet", 0xef, 0x6f);

        private static readonly NetworkItem?[] _networks =
        {
            LiveNet,
            TestNet
        };

        public static NetworkItem? GetFromPrivKeyPrefix(byte privKeyPrefix)
        {
            return (from network in _networks
                    where network.Value.PrivKeyPrefix == privKeyPrefix
                    select network).FirstOrDefault();
        }

        public static NetworkItem? GetFromPubKeyHash(byte pubKeyHash)
        {
            return (from network in _networks
                    where network.Value.PubKeyHash == pubKeyHash
                    select network).FirstOrDefault();
        }
    }
}
