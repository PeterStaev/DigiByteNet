using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace DigiByteNet
{
    public static class Helpers
    {
        public static ECPoint ECPointFromX(BigInteger x, bool odd)
        {
            var curve = Config.Curve.Curve;
            var xp = curve.FromBigInteger(x);
            var yp2 = xp.Square().Multiply(xp).Add(xp.Multiply(curve.A)).Add(curve.B);
            var yp = yp2.Sqrt();

            if (!yp.Square().Subtract(yp2).IsZero)
            {
                throw new ArgumentException("invalid point");
            }

            var yOdd = (yp.ToBigInteger().Mod(BigInteger.Two).CompareTo(BigInteger.One) == 0);
            if (odd != yOdd)
            {
                yp = yp.Negate();
            }

            return Config.Curve.Curve.CreatePoint(xp.ToBigInteger(), yp.ToBigInteger());
        }

        public static byte[] GetNumberBytes(long n)
        {
            using (var str = new MemoryStream())
            {
                using (var writer = new BinaryWriter(str))
                {
                    if (n < 253)
                    {
                        writer.Write((byte)n);
                    }
                    else if (n < 0x10000)
                    {
                        writer.Write((byte)253);
                        writer.Write((UInt16)n);
                    }
                    else if (n < 0x100000000)
                    {
                        writer.Write((byte)254);
                        writer.Write((UInt32)n);
                    }
                    else
                    {
                        writer.Write((byte)n);
                        writer.Write((Int32)n & -1);
                        writer.Write((UInt32)Math.Floor((decimal)n / 0x100000000));
                    }
                }

                return str.ToArray();
            }

        }

    }
}
