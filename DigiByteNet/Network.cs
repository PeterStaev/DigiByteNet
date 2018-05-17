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
