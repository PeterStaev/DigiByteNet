using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace DigiByteNet.Tests
{
    [TestClass]
    public class MessageUnitTest
    {
        [TestMethod]
        public void MagicHashShortString()
        {
            var testString = "Hello world!";
            var msg = new Message(testString);

            Assert.IsTrue(msg.Text.Length < 253);
            Assert.AreEqual("a0189cd9f632879ba344b69dd203e5f09addfea6289811803fe93fb3a5d56ecc", Helpers.GetHexString(msg.MagicHash()));
        }

        [TestMethod]
        public void MagicHashMediumString()
        {
            var testString = "Hello world! ";
            var sb = new StringBuilder();
            while (sb.Length < 253)
            {
                sb.Append(testString);
            }
            var msg = new Message(sb.ToString());

            Assert.IsTrue(msg.Text.Length >= 253 && msg.Text.Length < 0x10000);
            Assert.AreEqual("aba9e23328520392c7c8e152cf71ab7b9ff11a028ec01238e6d2b83273c3ce71", Helpers.GetHexString(msg.MagicHash()));
        }

        [TestMethod]
        public void MagicHashLongString()
        {
            var testString = "Hello world! ";
            var sb = new StringBuilder();
            while (sb.Length < 0x10000)
            {
                sb.Append(testString);
            }
            var msg = new Message(sb.ToString());

            Assert.IsTrue(msg.Text.Length >= 0x10000 && msg.Text.ToCharArray().LongLength < 0x100000000);
            Assert.AreEqual("c5d27dd2e681e7cfe34bd4b513e7f1314d691d1731377c42bef075649825cbcf", Helpers.GetHexString(msg.MagicHash()));
        }

        [TestMethod]
        public void SignVerify()
        {
            var priv = PrivateKey.FromWif("Kz3sAkMYRTwnXhi2UieoP4qKfMjpqYq7XWkqYR37pBgc3hqoimuq");
            var msg = new Message("Hello world!");
            var signature = msg.Sign(priv);

            Assert.IsNotNull(signature);
            Assert.AreNotEqual("", signature.ToString());

            Assert.IsTrue(msg.Verify("DNXLvN5A356fCvwDVXTAFwv6jQr1m7v9d4", signature.ToString()));
            Assert.IsFalse(msg.Verify("DHTXvgtoSVGHJGeZN7pSwLWyHY9ek9qdCh", signature.ToString()));
        }

        [TestMethod]
        public void SignVerifyNodeJsCompliance()
        {
            var msg = new Message("hello, world");
            var signature = Signature.FromCompact(Convert.FromBase64String("H8MWvge1AfdnbHeP079cFkm3PVHHNxo3aVZUS6/mJwKrAeWYd1PviKrcp4HIN/qD+d9Z7vPq9Zq64Qr26l5Kho4="));

            Assert.IsTrue(msg.Verify("DNXLvN5A356fCvwDVXTAFwv6jQr1m7v9d4", signature.ToString()));
            Assert.IsFalse(msg.Verify("DHTXvgtoSVGHJGeZN7pSwLWyHY9ek9qdCh", signature.ToString()));
        }
    }
}
