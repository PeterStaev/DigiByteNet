using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace DigiByteNet.Tests
{
    [TestClass]
    public class SignatureUnitTest
    {
        [TestMethod]
        public void FromCompactCompressed()
        {
            var compact = "H8MWvge1AfdnbHeP079cFkm3PVHHNxo3aVZUS6/mJwKrAeWYd1PviKrcp4HIN/qD+d9Z7vPq9Zq64Qr26l5Kho4=";
            var sign = Signature.FromCompact(Convert.FromBase64String(compact));

            Assert.AreEqual(compact, sign.ToString());
            Assert.AreEqual("88241187648749920796269330799968355783674585421634759266485511330795767661227", sign.R.ToString());
            Assert.AreEqual("857973108935340678351656014791032562443006579360014725381474321391829026446", sign.S.ToString());
        }

        [TestMethod]
        public void FromCompactUncompressed()
        {
            var compact = "HNXmGrW/0NFFCZeJTLGlPpF/idgutD8G+pbzLJbgYa7BL8EYjosNxVOiWIvitbaNu9fwkolKozl3hunHacU0jcY=";
            var sign = Signature.FromCompact(Convert.FromBase64String(compact));

            Assert.AreEqual(compact, sign.ToString());
            Assert.AreEqual("96749195918490682657328069582631179870862986886959457135468513384336296357569", sign.R.ToString());
            Assert.AreEqual("21599874851784571661593176657075588065282326878264884360491123696105885568454", sign.S.ToString());
        }
    }
}
