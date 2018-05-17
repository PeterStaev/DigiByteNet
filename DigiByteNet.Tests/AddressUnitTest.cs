using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace DigiByteNet.Tests
{
    [TestClass]
    public class AddressUnitTest
    {
        private readonly string _goodAddressString = "DNXLvN5A356fCvwDVXTAFwv6jQr1m7v9d4";

        [TestMethod]
        public void FromStringGood()
        {
            var address = Address.FromString(this._goodAddressString);
            Assert.AreEqual(this._goodAddressString, address.ToString());
        }

        [TestMethod]
        public void FromStringBad()
        {
            Assert.ThrowsException<ArgumentException>(() => Address.FromString("14fjysmpwLvSsAskvLASw6ek5XfhTzskHC"));
        }


        [TestMethod]
        public void FromPublicKeyGood()
        {
            var pubKey = PublicKey.FromPrivateKey(PrivateKey.FromWif("Kz3sAkMYRTwnXhi2UieoP4qKfMjpqYq7XWkqYR37pBgc3hqoimuq"));
            var address = Address.FromPublicKey(pubKey);
            Assert.AreEqual(this._goodAddressString, address.ToString());
        }

        [TestMethod]
        public void FromPublicKeyBad()
        {
            var pubKey = PublicKey.FromPrivateKey(PrivateKey.FromWif("L1cT9LpRSSDGTybdoF3yuESbcMQiRLiFiCAvVLmC9BiEXsVXUABE"));
            var address = Address.FromPublicKey(pubKey);
            Assert.AreNotEqual(this._goodAddressString, address.ToString());
        }
    }
}
