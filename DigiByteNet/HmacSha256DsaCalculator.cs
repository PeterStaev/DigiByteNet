using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace DigiByteNet
{
    public class HmacSha256DsaCalculator : IDsaKCalculator
    {
        private byte[] _v;
        private byte[] _k;
        private BigInteger _N;

        #region IDsaKCalculator implementation

        public bool IsDeterministic { get { return true; } }

        public void Init(BigInteger n, SecureRandom random)
        {
            throw new NotImplementedException();
        }

        public void Init(BigInteger n, BigInteger d, byte[] message)
        {
            this._N = n;
            this._v = Enumerable.Repeat<byte>(0x01, 32).ToArray();
            this._k = Enumerable.Repeat<byte>(0x00, 32).ToArray();

            var x = d.ToByteArray();

            using (var hmacsha256 = new HMACSHA256(this._k))
            {
                this._k = hmacsha256.ComputeHash(this._v.Concat(new byte [0x00]).Concat(x).Concat(message).ToArray());
            }

            using (var hmacsha256 = new HMACSHA256(this._k))
            {
                this._v = hmacsha256.ComputeHash(this._v);
                this._k = hmacsha256.ComputeHash(this._v.Concat(new byte[0x01]).Concat(x).Concat(message).ToArray());
            }

            using (var hmacsha256 = new HMACSHA256(this._k))
            {
                this._v = hmacsha256.ComputeHash(this._v);
                this._v = hmacsha256.ComputeHash(this._v);
            }

            var T = new BigInteger(1, this._v);
            while(!(T.CompareTo(this._N) < 0 && T.SignValue == 1))
            {
                T = this.GetNextT();
            }
        }

        public BigInteger NextK()
        {
            var res = new BigInteger(1, this._v);

            BigInteger T;
            do
            {
                T = this.GetNextT();
            }
            while (!(T.CompareTo(this._N) < 0 && T.SignValue == 1));

            return res;
        }

        private BigInteger GetNextT()
        {
            using (var hmacsha256 = new HMACSHA256(this._k))
            {
                this._k = hmacsha256.ComputeHash(this._v.Concat(new byte[0x00]).ToArray());
            }
            using (var hmacsha256 = new HMACSHA256(this._k))
            {
                this._v = hmacsha256.ComputeHash(this._v);
                this._v = hmacsha256.ComputeHash(this._v);
            }

            return new BigInteger(1, this._v);
        }

        #endregion
    }
}
