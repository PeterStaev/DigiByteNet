﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace DigiByteNet
{
    class DgbECDsaSigner : ECDsaSigner
    {
        private BigInteger _k;

        public DgbECDsaSigner() : base(new HmacSha256DsaCalculator())
        {
        }

        public override BigInteger[] GenerateSignature(byte[] message)
        {
            var ec = this.key.Parameters;
            var e = new BigInteger(1, message);
            var d = ((ECPrivateKeyParameters)this.key).D;
            var badrs = 0;
            BigInteger r;
            BigInteger s;

            this.kCalculator.Init(ec.N, d, message);
            
            do
            {
                if (this._k == null || badrs > 0)
                {
                    this._k = this.kCalculator.NextK();
                }
                badrs++;

                var k = this._k;
                var Q = ec.G.Multiply(k).Normalize();
                r = Q.AffineXCoord.ToBigInteger().Mod(ec.N);
                s = k.ModInverse(ec.N).Multiply(e.Add(d.Multiply(r))).Mod(ec.N);
            }
            while (r.SignValue <= 0 || s.SignValue <= 0);

            s = this.ToLowS(s);

            return new BigInteger[] { r, s };
        }

        public override bool VerifySignature(byte[] message, BigInteger r, BigInteger s)
        {
            if (message.Length != 32)
            {
                return false;
            }

            var N = this.key.Parameters.N;

            if (!(r.SignValue == 1 && r.CompareTo(N) == -1 || !(s.SignValue == 1 && s.CompareTo(N) == -1)))
            {
                return false;
            }

            var e = new BigInteger(1, message);
            var sinv = s.ModInverse(N);
            var u1 = sinv.Multiply(e).Mod(N);
            var u2 = sinv.Multiply(r).Mod(N);
            var Q = ((ECPublicKeyParameters)this.key).Q;

            
            var p = ECAlgorithms.SumOfTwoMultiplies(this.key.Parameters.G, u1, Q, u2).Normalize();
            if (p.IsInfinity)
            {
                return false;
            }

            if (p.AffineXCoord.ToBigInteger().Mod(N).CompareTo(r) != 0)
            {
                return false;//'Invalid signature';
            }
            else
            {
                return true;
            }

        }

        public void Init(bool forSigning, ICipherParameters parameters, bool initRandomK)
        {
            base.Init(forSigning, parameters);
            
            if (forSigning)
            {
                var signParams = (ECPrivateKeyParameters)parameters;
                var d = signParams.D;

                if (initRandomK)
                {
                    var N = signParams.Parameters.N;

                    BigInteger k;
                    byte[] data = new byte[32];
                    using (var rng = new RNGCryptoServiceProvider())
                    {
                        do
                        {
                            rng.GetBytes(data);
                            k = new BigInteger(1, data);
                        }
                        while (!(k.CompareTo(N) < 0 && k.SignValue == 1));
                    }

                    this._k = k;
                }
            }
        }
        
        private BigInteger ToLowS(BigInteger s)
        {
            // https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
            var N = this.key.Parameters.N;
            if (s.CompareTo(N.Divide(BigInteger.Two)) > 0)
            {
                s = N.Subtract(s);
            }

            return s;
        }
    }
}
