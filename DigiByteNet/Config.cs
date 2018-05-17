using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DigiByteNet
{
    public static class Config
    {
        public static readonly X9ECParameters Curve = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
        public static readonly ECDomainParameters ECDomain = new ECDomainParameters(Curve.Curve, Curve.G, Curve.N, Curve.H);
    }
}
