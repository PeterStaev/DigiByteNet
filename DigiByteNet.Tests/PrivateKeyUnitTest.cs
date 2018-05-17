using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Math;

namespace DigiByteNet.Tests
{
    [TestClass]
    public class PrivateKeyUnitTest
    {
        [TestMethod]
        public void CreateNew()
        {
            var priv = new PrivateKey();
            Assert.AreEqual(1, priv.BN.CompareTo(BigInteger.Zero));
            Assert.IsTrue(priv.Compressed);
            Assert.AreEqual(Network.LiveNet, priv.Network);
        }

        [TestMethod]
        public void FromWifLivenetCompressed()
        {
            var wif = "L1cT9LpRSSDGTybdoF3yuESbcMQiRLiFiCAvVLmC9BiEXsVXUABE";
            var priv = PrivateKey.FromWif(wif);

            Assert.AreEqual(wif, priv.ToWif());
            Assert.AreEqual(Network.LiveNet, priv.Network);
            Assert.IsTrue(priv.Compressed);
        }

        [TestMethod]
        public void FromWifLivenetUncompressed()
        {
            var wif = "5JxgQaFM1FMd38cd14e3mbdxsdSa9iM2BV6DHBYsvGzxkTNQ7Un";
            var priv = PrivateKey.FromWif(wif);

            Assert.AreEqual(wif, priv.ToWif());
            Assert.AreEqual(Network.LiveNet, priv.Network);
            Assert.IsFalse(priv.Compressed);
        }

        [TestMethod]
        public void FromWifTestnetCompressed()
        {
            var wif = "cSdkPxkAjA4HDr5VHgsebAPDEh9Gyub4HK8UJr2DFGGqKKy4K5sG";
            var priv = PrivateKey.FromWif(wif);

            Assert.AreEqual(wif, priv.ToWif());
            Assert.AreEqual(Network.TestNet, priv.Network);
            Assert.IsTrue(priv.Compressed);
        }

        [TestMethod]
        public void FromWifTestnetUncompressed()
        {
            var wif = "92jJzK4tbURm1C7udQXxeCBvXHoHJstDXRxAMouPG1k1XUaXdsu";
            var priv = PrivateKey.FromWif(wif);

            Assert.AreEqual(wif, priv.ToWif());
            Assert.AreEqual(Network.TestNet, priv.Network);
            Assert.IsFalse(priv.Compressed);
        }

        [TestMethod]
        public void FromWifBad()
        {
            Assert.ThrowsException<ArgumentException>(() => PrivateKey.FromWif("74pxNKNpByQ2kMow4d9kF6Z77BYeKztQNLq3dSyU4ES1K5KLNiz"));
            Assert.ThrowsException<FormatException>(() => PrivateKey.FromWif("Kz3sAkMYRTwnXhi2UieoP4qKfMjpqYq7XWkqYR37pBgc3hqoimua"));
        }

        [TestMethod]
        public void ToPublicKey()
        {
            Assert.IsNotNull(PrivateKey.FromWif("Kz3sAkMYRTwnXhi2UieoP4qKfMjpqYq7XWkqYR37pBgc3hqoimuq").ToPublicKey());
        }
    }
}
