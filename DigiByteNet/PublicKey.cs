using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace DigiByteNet
{
    public class PublicKey
    {
        public ECPoint Point { get; }
        public bool Compressed { get; }
        public NetworkItem Network { get; }

        private PublicKey(ECPoint point, bool compressed, NetworkItem network)
        {
            this.Point = point;
            this.Compressed = compressed;
            this.Network = network;
        }

        public byte[] ToByteArray()
        {
            return this.Point.GetEncoded(this.Compressed);
        }

        public Address ToAddress()
        {
            return Address.FromPublicKey(this);
        }

        public static PublicKey FromPrivateKey(PrivateKey priv)
        {
            var point = Config.Curve.G.Multiply(new BigInteger(1, priv.BN.ToByteArray()));
            return new PublicKey(point, priv.Compressed, priv.Network);
        }

        public static PublicKey FromPoint(ECPoint point, bool compressed)
        {
            return new PublicKey(point, compressed, DigiByteNet.Network.LiveNet);
        }
    }
}
