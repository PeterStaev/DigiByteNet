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
