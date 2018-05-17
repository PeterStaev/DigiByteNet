using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace DigiByteNet
{
    public class Signature
    {
        private byte _I;

        public BigInteger R { get; }
        public BigInteger S { get; }
        public bool Compressed { get; }
        public byte[] Data { get; set; }

        private Signature(BigInteger r, BigInteger s, byte i, bool compressed)
        {
            this.R = r;
            this.S = s;
            this._I = i;
            this.Compressed = compressed;
        }

        public Signature(BigInteger r, BigInteger s, byte[] data, PublicKey pub)
        {
            this.R = r;
            this.S = s;
            this.Data = data;
            this.CalculateI(pub);
            this.Compressed = pub.Compressed;
        }

        public PublicKey GetPublicKey()
        {
            var i = this._I;
            if (i < 0 || i > 3)
            {
                throw new ArgumentException("i is not valid");
            }

            var e = new BigInteger(1, this.Data);
            var r = this.R;
            var s = this.S;

            // A set LSB signifies that the y-coordinate is odd
            var isYOdd = Convert.ToBoolean(i & 1);

            // The more significant bit specifies whether we should use the
            // first or second candidate key.
            var isSecondKey = Convert.ToBoolean(i >> 1);

            var N = Config.Curve.N;
            var G = Config.Curve.G;

            // 1.1 Let x = r + jn
            var x = isSecondKey ? r.Add(N) : r;
            var R = Helpers.ECPointFromX(x, isYOdd);

            // 1.4 Check that nR is at infinity
            var nR = R.Multiply(N);

            if (!nR.IsInfinity)
            {
                throw new Exception("nR is not a valid curve point");
            }

            // Compute -e from e
            var eNeg = e.Negate().Mod(N);

            // 1.6.1 Compute Q = r^-1 (sR - eG)
            // Q = r^-1 (sR + -eG)
            var rInv = r.ModInverse(N);

            //var Q = R.multiplyTwo(s, G, eNeg).mul(rInv);
            var Q = R.Multiply(s).Add(G.Multiply(eNeg)).Multiply(rInv).Normalize();

            var pubkey = PublicKey.FromPoint(Q, this.Compressed);

            return pubkey;

        }

        public byte[] ToCompact()
        {
           
            if (this._I < 0 || this._I > 3)
            {
                throw new Exception("i must be equal to 0, 1, 2, or 3");
            }

            var val = this._I + 27 + 4;
            if (!this.Compressed)
            {
                val = val - 4;
            }

            using (var str = new MemoryStream())
            {
                str.WriteByte((byte)val);

                var rData = this.R.ToByteArray();
                str.Write(rData, (rData[0] == 0 ? 1 : 0), 32);

                var sData = this.S.ToByteArray();
                str.Write(sData, (sData[0] == 0 ? 1 : 0), 32);

                return str.ToArray();
            }
        }

        public override string ToString()
        {
            return Convert.ToBase64String(this.ToCompact());
        }

        public static Signature FromCompact(byte[] value)
        {
            var compressed = true;
            var i = value[0] - 27 - 4;
            if (i < 0)
            {
                compressed = false;
                i = i + 4;
            }

            var b2 = value.Skip(1).Take(32).ToArray();
            var b3 = value.Skip(33).Take(32).ToArray();

            if (i < 0 || i > 3)
            {
                throw new ArgumentException("invalid i");
            }

            return new Signature(new BigInteger(1, b2), new BigInteger(1, b3), (byte)i, compressed);
        }

        private void CalculateI(PublicKey pub)
        {
            for (var i = 0; i < 4; i++)
            {
                this._I = (byte)i;
                PublicKey Qprime;
                try
                {
                    Qprime = this.GetPublicKey();
                }
                catch
                {
                    continue;
                }

                if (Qprime.Point.Equals(pub.Point))
                {
                    return;
                }
            }

            throw new Exception("Unable to find valid recovery factor");
        }
    }
}
