using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Math.EC;

namespace DigiByteNet.Tests
{
    [TestClass]
    public class PublicKeyUnitTest
    {
        [TestMethod]
        public void FromPrivateKeyLivenetCompressed()
        {
            var priv = PrivateKey.FromWif("Kz3sAkMYRTwnXhi2UieoP4qKfMjpqYq7XWkqYR37pBgc3hqoimuq");
            var pub = PublicKey.FromPrivateKey(priv);

            Assert.AreEqual("020d072ff096bf53b7c6c85854655f3eb675c48ca14e3a24dc7cce00524c26a7ba", Helpers.GetHexString(pub.ToByteArray()));
            Assert.AreEqual(priv.Compressed, pub.Compressed);
            Assert.AreEqual(priv.Network, pub.Network);
            Assert.AreEqual("DNXLvN5A356fCvwDVXTAFwv6jQr1m7v9d4", pub.ToAddress().ToString());
        }

        [TestMethod]
        public void FromPrivateKeyLivenetUncompressed()
        {
            var priv = PrivateKey.FromWif("5JxgQaFM1FMd38cd14e3mbdxsdSa9iM2BV6DHBYsvGzxkTNQ7Un");
            var pub = PublicKey.FromPrivateKey(priv);

            Assert.AreEqual("0429766f1afa25ca499a51f8e01c292b0255a21a41bb6685564a1607a811ffe92458ee8923b3e93566d0b15778b168fe0027d63d0c7c7561a841222f9f32e13eca", Helpers.GetHexString(pub.ToByteArray()));
            Assert.AreEqual(priv.Compressed, pub.Compressed);
            Assert.AreEqual(priv.Network, pub.Network);
            Assert.AreEqual("DQe6BLwtWhq9dv1zy4EUT6AgGg8sVahTX2", pub.ToAddress().ToString());
        }

        [TestMethod]
        public void FromPrivateKeyTestnetCompressed()
        {
            var priv = PrivateKey.FromWif("cSdkPxkAjA4HDr5VHgsebAPDEh9Gyub4HK8UJr2DFGGqKKy4K5sG");
            var pub = PublicKey.FromPrivateKey(priv);

            Assert.AreEqual("0229766f1afa25ca499a51f8e01c292b0255a21a41bb6685564a1607a811ffe924", Helpers.GetHexString(pub.ToByteArray()));
            Assert.AreEqual(priv.Compressed, pub.Compressed);
            Assert.AreEqual(priv.Network, pub.Network);
            Assert.AreEqual("mgY65WSfEmsyYaYPQaXhmXMeBhwp4EcsQW", pub.ToAddress().ToString());
        }

        [TestMethod]
        public void FromPrivateKeyTestnetUncompressed()
        {
            var priv = PrivateKey.FromWif("92jJzK4tbURm1C7udQXxeCBvXHoHJstDXRxAMouPG1k1XUaXdsu");
            var pub = PublicKey.FromPrivateKey(priv);

            Assert.AreEqual("0429766f1afa25ca499a51f8e01c292b0255a21a41bb6685564a1607a811ffe92458ee8923b3e93566d0b15778b168fe0027d63d0c7c7561a841222f9f32e13eca", Helpers.GetHexString(pub.ToByteArray()));
            Assert.AreEqual(priv.Compressed, pub.Compressed);
            Assert.AreEqual(priv.Network, pub.Network);
            Assert.AreEqual("n11ww96E2KN7t2K1x3DHjFDQFY1H2UsMdB", pub.ToAddress().ToString());
        }
    }
}
