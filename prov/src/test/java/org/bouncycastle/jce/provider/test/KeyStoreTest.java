package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Exercise the various key stores, making sure we at least get back what we put in!
 * <p>
 * This tests both the BKS, and the UBER key store.
 */
public class KeyStoreTest
    extends SimpleTest
{
    static char[]   passwd = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd' };

    byte[] v1BKS = Base64.decode(
          "AAAAAQAAABTqZbNMyPjsFazhFplWWDMBLPRdRAAABcYEAAdhbmRyb2lkAAAB"
        + "NOifkPwAAAAAAAAAPAAAABTZOLhcyhB0gKyfoDvyQbpzftB7GgAABEYPrZP8"
        + "q20AJLETjDv0K9C5rIl1erpyvpv20bqcbghK6wD0b8OP5/XzOz/8knhxmqJZ"
        + "3yRJMw==");
    byte[] v2BKS = Base64.decode(
          "AAAAAgAAABSkmTXz4VIznO1SSUqsIHdxWcxsuQAABFMEAAdhbmRyb2lkAAABN" +
          "OifkPwAAAAAAAAAPAAAABTZOLhcyhB0gKyfoDvyQbpzftB7GgAABEYPrZP8q2" +
          "0AJLETjDv0K9C5rIl1erpyvpv20bqcbghK6wBO59KOGPvSrmJpd32P6ZAh9qLZJw==");

    byte[] v1UBER = Base64.decode(
          "AAAAAQAAABRP0F6p2p3FyQKqyJiJt3NbvdybiwAAB2znqrO779YIW5gMtbt+"
        + "NUs96VPPcfZiKJPg7RKH7Yu3CQB0/g9nYsvgFB0fQ05mHcW3KjntN2/31A6G"
        + "i00n4ZnUTjJL16puZnQrloeGXxFy58tjwkFuwJ7V7ELYgiZlls0beHSdDGQW"
        + "iyYECwWs1la/");
    byte[] v2UBER = Base64.decode(
          "AAAAAgAAABQ/D9k3376OG/REg4Ams9Up332tLQAABujoVcsRcKWwhlo4mMg5"
        + "lF2vJfK+okIYecJGWCvdykF5r8kDn68llt52IDXDkpRXVXcNJ0/aD7sa7iZ0"
        + "SL0TAwcfp/9v4j/w8slj/qgO0i/76+zROrP0NGFIa5k/iOg5Z0Tj77muMaJf"
        + "n3vLlIHa4IsX");

    byte[] negSaltBKS = Base64.decode(
          "AAAAAv////+WnyglO06djy6JgCxGiIemnZdcOwAAB2AEAAdhbmRyb2lkAAAB" +
          "NOifkPwAAAAAAAAAPAAAABTZOLhcyhB0gKyfoDvyQbpzftB7GgAABEYPrZP8" +
          "q20AJLETjDv0K9C5rIl1erpyvpv20bqcbghK6wDrg6gUHsh27wNjUwkR+REe" +
          "NeFYBg==");

    char[] oldStorePass = "fredfred".toCharArray();

    public void ecStoreTest(
        String  storeName)
        throws Exception
    {
        X9ECParameters x9 = ECNamedCurveTable.getByName("prime239v1");
        ECCurve curve = x9.getCurve();
        ECParameterSpec ecSpec = new ECParameterSpec(curve, x9.getG(), x9.getN(), x9.getH());

        KeyPairGenerator    g = KeyPairGenerator.getInstance("ECDSA", "BC");

        g.initialize(ecSpec, new SecureRandom());

        KeyPair     keyPair = g.generateKeyPair();

        PublicKey   pubKey = keyPair.getPublic();
        PrivateKey  privKey = keyPair.getPrivate();

        //
        // distinguished name table.
        //
        X500NameBuilder nBldr = new X500NameBuilder();

        nBldr.addRDN(BCStyle.C, "AU");
        nBldr.addRDN(BCStyle.O,"The Legion of the Bouncy Castle");
        nBldr.addRDN(BCStyle.L, "Melbourne");
        nBldr.addRDN(BCStyle.ST,"Victoria");
        nBldr.addRDN(BCStyle.E, "feedback-crypto@bouncycastle.org");
        
        Certificate[]    chain = new Certificate[1];

        try
        {
            X509Certificate cert = TestCertificateGen.createSelfSignedCert(nBldr.build(), "SHA1withECDSA", new KeyPair(pubKey, privKey));

            cert.checkValidity(new Date());

            cert.verify(pubKey);

            ByteArrayInputStream    bIn = new ByteArrayInputStream(cert.getEncoded());
            CertificateFactory      fact = CertificateFactory.getInstance("X.509", "BC");

            cert = (X509Certificate)fact.generateCertificate(bIn);

            chain[0] = cert;
        }
        catch (Exception e)
        {
            fail("error generating cert - " + e.toString());
        }

        KeyStore store = KeyStore.getInstance(storeName, "BC");

        store.load(null, null);

        store.setKeyEntry("private", privKey, passwd, chain);

        //
        // write out and read back store
        //
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();

        store.store(bOut, passwd);

        ByteArrayInputStream    bIn = new ByteArrayInputStream(bOut.toByteArray());

        //
        // start with a new key store
        //
        store = KeyStore.getInstance(storeName, "BC");

        store.load(bIn, passwd);

        //
        // load the private key
        //
        privKey = (PrivateKey)store.getKey("private", passwd);

        //
        // double public key encoding test
        //
        byte[]              pubEnc = pubKey.getEncoded();
        KeyFactory          keyFac = KeyFactory.getInstance(pubKey.getAlgorithm(), "BC");
        X509EncodedKeySpec  pubX509 = new X509EncodedKeySpec(pubEnc);

        pubKey = (PublicKey)keyFac.generatePublic(pubX509);

        pubEnc = pubKey.getEncoded();
        keyFac = KeyFactory.getInstance(pubKey.getAlgorithm(), "BC");
        pubX509 = new X509EncodedKeySpec(pubEnc);

        pubKey = (PublicKey)keyFac.generatePublic(pubX509);

        //
        // double private key encoding test
        //
        byte[]              privEnc = privKey.getEncoded();

        keyFac = KeyFactory.getInstance(privKey.getAlgorithm(), "BC");

        PKCS8EncodedKeySpec privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
        privKey = (PrivateKey)keyFac.generatePrivate(privPKCS8);

        keyFac = KeyFactory.getInstance(privKey.getAlgorithm(), "BC");
        privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
        privKey = (PrivateKey)keyFac.generatePrivate(privPKCS8);
    }

    public void keyStoreTest(
        String    storeName)
        throws Exception
    {
        KeyStore store = KeyStore.getInstance(storeName, "BC");

        store.load(null, null);

        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "BC");

        gen.initialize(1024, new SecureRandom());

        KeyPair         pair = gen.generateKeyPair();
        RSAPrivateKey   privKey = (RSAPrivateKey)pair.getPrivate();
        RSAPublicKey    pubKey = (RSAPublicKey)pair.getPublic();
        BigInteger      modulus = privKey.getModulus();
        BigInteger      privateExponent = privKey.getPrivateExponent();


        //
        // distinguished name table.
        //
        X500NameBuilder nBldr = new X500NameBuilder();

        nBldr.addRDN(BCStyle.C, "AU");
        nBldr.addRDN(BCStyle.O,"The Legion of the Bouncy Castle");
        nBldr.addRDN(BCStyle.L, "Melbourne");
        nBldr.addRDN(BCStyle.ST,"Victoria");
        nBldr.addRDN(BCStyle.E, "feedback-crypto@bouncycastle.org");

        //
        // extensions
        //

        //
        // create the certificate.
        //
        Certificate[]   chain = new Certificate[1];

        try
        {
            X509Certificate cert = TestCertificateGen.createSelfSignedCert(nBldr.build(), "MD5WithRSAEncryption", new KeyPair(pubKey, privKey));

            cert.checkValidity(new Date());

            cert.verify(pubKey);

            ByteArrayInputStream    bIn = new ByteArrayInputStream(cert.getEncoded());
            CertificateFactory      fact = CertificateFactory.getInstance("X.509", "BC");

            cert = (X509Certificate)fact.generateCertificate(bIn);

            chain[0] = cert;
        }
        catch (Exception e)
        {
            fail("error generating cert - " + e.toString());
        }

        store.setKeyEntry("private", privKey, passwd, chain);

        //
        // write out and read back store
        //
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();

        store.store(bOut, passwd);

        ByteArrayInputStream    bIn = new ByteArrayInputStream(bOut.toByteArray());

        //
        // start with a new key store
        //
        store = KeyStore.getInstance(storeName, "BC");

        store.load(bIn, passwd);

        //
        // verify public key
        //
        privKey = (RSAPrivateKey)store.getKey("private", passwd);

        if (!privKey.getModulus().equals(modulus))
        {
            fail("private key modulus wrong");
        }
        else if (!privKey.getPrivateExponent().equals(privateExponent))
        {
            fail("private key exponent wrong");
        }

        //
        // verify certificate
        //
        Certificate cert = store.getCertificateChain("private")[0];

        cert.verify(pubKey);
    }

    // CVE-2018-5382: the default BKS keystore must refuse to load a legacy version 0/1 store
    // (which derives a 16-bit, brute-forceable HMAC integrity key) unless the caller has explicitly
    // opted in via org.bouncycastle.bks.enable_v1. The test harness sets that system property, so
    // we override it off on this thread to exercise the default behaviour.
    private void v1RejectedByDefaultTest()
        throws Exception
    {
        Properties.setThreadOverride(Properties.BKS_ENABLE_V1, false);
        try
        {
            KeyStore ks = KeyStore.getInstance("BKS", "BC");

            ks.load(new ByteArrayInputStream(v1BKS), oldStorePass);

            fail("default BKS loaded a version 1 store without " + Properties.BKS_ENABLE_V1);
        }
        catch (IOException e)
        {
            if (!e.getMessage().startsWith("BKS version 1 keystore not supported"))
            {
                fail("unexpected exception: " + e.getMessage());
            }
        }
        finally
        {
            Properties.removeThreadOverride(Properties.BKS_ENABLE_V1);
        }
    }

    // CVE-2018-5382: version 0 stores use the same weak HMAC key derivation as version 1, so a
    // store whose (unauthenticated) version field has been rewritten to 0 must be refused too.
    private void v0RejectedByDefaultTest()
        throws Exception
    {
        byte[] v0BKS = (byte[])v1BKS.clone();
        v0BKS[3] = 0;

        Properties.setThreadOverride(Properties.BKS_ENABLE_V1, false);
        try
        {
            KeyStore ks = KeyStore.getInstance("BKS", "BC");

            ks.load(new ByteArrayInputStream(v0BKS), oldStorePass);

            fail("default BKS loaded a version 0 store without " + Properties.BKS_ENABLE_V1);
        }
        catch (IOException e)
        {
            if (!e.getMessage().startsWith("BKS version 1 keystore not supported"))
            {
                fail("unexpected exception: " + e.getMessage());
            }
        }
        finally
        {
            Properties.removeThreadOverride(Properties.BKS_ENABLE_V1);
        }

        // with the opt-in the legacy store is still readable
        Properties.setThreadOverride(Properties.BKS_ENABLE_V1, true);
        try
        {
            checkStore(KeyStore.getInstance("BKS", "BC"), v0BKS);
        }
        finally
        {
            Properties.removeThreadOverride(Properties.BKS_ENABLE_V1);
        }
    }

    private void oldStoreTest()
        throws Exception
    {
        checkStore(KeyStore.getInstance("BKS", "BC"), v1BKS);
        checkStore(KeyStore.getInstance("BKS", "BC"), v2BKS);
        checkStore(KeyStore.getInstance("UBER", "BC"), v1UBER);
        checkStore(KeyStore.getInstance("UBER", "BC"), v2UBER);

        checkOldStore(KeyStore.getInstance("BKS-V1", "BC"), v1BKS);
        checkOldStore(KeyStore.getInstance("BKS-V1", "BC"), v2BKS);
    }

    private void checkStore(KeyStore ks, byte[] data)
        throws Exception
    {
        ks.load(new ByteArrayInputStream(data), oldStorePass);

        if (!ks.containsAlias("android"))
        {
            fail("cannot find alias");
        }

        Key key = ks.getKey("android", oldStorePass);
        if (key == null)
        {
            fail("cannot find key");
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        ks.store(bOut, oldStorePass);
    }

    private void checkOldStore(KeyStore ks, byte[] data)
        throws Exception
    {
        ks.load(new ByteArrayInputStream(data), oldStorePass);

        if (!ks.containsAlias("android"))
        {
            fail("cannot find alias");
        }

        Key key = ks.getKey("android", oldStorePass);
        if (key == null)
        {
            fail("cannot find key");
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        ks.store(bOut, oldStorePass);

        if (data.length != bOut.toByteArray().length)
        {
            fail("Old version key store write incorrect");
        }
    }

    private void checkException()
        throws Exception
    {
        KeyStore ks = KeyStore.getInstance("BKS", "BC");

        try
        {
            ks.load(new ByteArrayInputStream(negSaltBKS), oldStorePass);
        }
        catch (IOException e)
        {
            if (!e.getMessage().equals("Invalid salt detected"))
            {
                fail("negative salt length not detected");
            }
        }

        X9ECParameters x9 = ECNamedCurveTable.getByName("prime239v1");
        ECCurve curve = x9.getCurve();
        ECParameterSpec ecSpec = new ECParameterSpec(curve, x9.getG(), x9.getN(), x9.getH());

        KeyPairGenerator    g = KeyPairGenerator.getInstance("ECDSA", "BC");

        g.initialize(ecSpec, new SecureRandom());

        KeyPair     keyPair = g.generateKeyPair();

        PublicKey   pubKey = keyPair.getPublic();
        PrivateKey  privKey = keyPair.getPrivate();

        //
        // distinguished name table.
        //
        X500NameBuilder nBldr = new X500NameBuilder();

        nBldr.addRDN(BCStyle.C, "AU");
        nBldr.addRDN(BCStyle.O,"The Legion of the Bouncy Castle");
        nBldr.addRDN(BCStyle.L, "Melbourne");
        nBldr.addRDN(BCStyle.ST,"Victoria");
        nBldr.addRDN(BCStyle.E, "feedback-crypto@bouncycastle.org");

        //
        // create the certificate - version 3
        //
        Certificate[]    dummyChain = new Certificate[1];

        dummyChain[0] = TestCertificateGen.createSelfSignedCert(nBldr.build(), "SHA1withECDSA", new KeyPair(pubKey, privKey));

        ks = KeyStore.getInstance("BKS", "BC");

        ks.load(null, null);

        // add a "protected key" should work
        ks.setKeyEntry("noenc", new PrivateKey()
        {
            public String getAlgorithm()
            {
                return null;
            }

            public String getFormat()
            {
                return null;
            }

            public byte[] getEncoded()
            {
                return null;
            }
        }, new char[0], dummyChain);

        try
        {
            ks.store(new ByteArrayOutputStream(), "hello".toCharArray());
        }
        catch (IOException e)
        {
            isTrue("unable to store encoding of protected key".equals(e.getMessage()));
        }
    }

    public String getName()
    {
        return "KeyStore";
    }

    public void performTest()
        throws Exception
    {
        keyStoreTest("BKS");
        keyStoreTest("UBER");

        keyStoreTest("BKS-V1");

        ecStoreTest("BKS");
        oldStoreTest();
        v1RejectedByDefaultTest();
        v0RejectedByDefaultTest();
        checkException();
        checkOversizedEntryRejected();
        checkOversizedEncodingRejected();
        checkOversizedUberEntryRejected();
        checkOversizedSealedSaltRejected();
        checkLargeEntryStreamed();
    }

    /*
     * The certificate and key encodings decoded for each entry are length-prefixed too: an
     * Integer.MAX_VALUE encoding length in a CERTIFICATE entry, in a certificate of a KEY entry's
     * chain, or in a KEY entry's key encoding must fail with an IOException after a bounded
     * allocation rather than an OutOfMemoryError.
     */
    private void checkOversizedEncodingRejected()
        throws Exception
    {
        char[][] passwords = {null, new char[0], "test".toCharArray()};

        // BKS: a CERTIFICATE entry whose certificate encoding declares Integer.MAX_VALUE bytes.
        ByteArrayOutputStream certPoison = new ByteArrayOutputStream();
        DataOutputStream c = new DataOutputStream(certPoison);
        c.writeInt(2);                              // store version
        c.writeInt(20);                             // salt length
        c.write(new byte[20]);                      // salt
        c.writeInt(1024);                           // iteration count
        c.write(1);                                 // entry type = CERTIFICATE
        c.writeUTF("evil");                         // alias
        c.writeLong(System.currentTimeMillis());    // creation date
        c.writeInt(0);                              // chain length
        c.writeUTF("X.509");                        // certificate type
        c.writeInt(Integer.MAX_VALUE);              // poison certificate encoding length

        // BKS: a KEY entry whose single chain certificate declares Integer.MAX_VALUE bytes.
        ByteArrayOutputStream chainCertPoison = new ByteArrayOutputStream();
        DataOutputStream cc = new DataOutputStream(chainCertPoison);
        cc.writeInt(2);
        cc.writeInt(20);
        cc.write(new byte[20]);
        cc.writeInt(1024);
        cc.write(2);                                // entry type = KEY
        cc.writeUTF("evil");
        cc.writeLong(System.currentTimeMillis());
        cc.writeInt(1);                             // chain length
        cc.writeUTF("X.509");                       // certificate type
        cc.writeInt(Integer.MAX_VALUE);             // poison certificate encoding length

        // BKS: a KEY entry whose key encoding declares Integer.MAX_VALUE bytes.
        ByteArrayOutputStream keyPoison = new ByteArrayOutputStream();
        DataOutputStream k = new DataOutputStream(keyPoison);
        k.writeInt(2);
        k.writeInt(20);
        k.write(new byte[20]);
        k.writeInt(1024);
        k.write(2);                                 // entry type = KEY
        k.writeUTF("evil");
        k.writeLong(System.currentTimeMillis());
        k.writeInt(0);                              // chain length
        k.write(0);                                 // key type = private
        k.writeUTF("PKCS#8");                       // key format
        k.writeUTF("RSA");                          // key algorithm
        k.writeInt(Integer.MAX_VALUE);              // poison key encoding length

        for (int p = 0; p != passwords.length; p++)
        {
            loadShouldRejectNotOOM("BKS", certPoison.toByteArray(), passwords[p]);
            loadShouldRejectNotOOM("BKS", chainCertPoison.toByteArray(), passwords[p]);
            loadShouldRejectNotOOM("BKS", keyPoison.toByteArray(), passwords[p]);
        }
    }

    /*
     * The UBER store body is encrypted under the store password, so the poisoned entry is only
     * reached once it has been decrypted - the same unbounded allocation must still be refused
     * on that load path.
     */
    private void checkOversizedUberEntryRejected()
        throws Exception
    {
        char[] password = "test".toCharArray();
        byte[] salt = new byte[20];
        int iterationCount = 1024;

        // the entries, as they appear once the UBER body is decrypted
        ByteArrayOutputStream blobBody = new ByteArrayOutputStream();
        DataOutputStream b = new DataOutputStream(blobBody);
        b.write(3);                                 // entry type = SECRET
        b.writeUTF("evil");
        b.writeLong(System.currentTimeMillis());
        b.writeInt(0);                              // chain length
        b.writeInt(Integer.MAX_VALUE);              // poison blob length

        ByteArrayOutputStream chainBody = new ByteArrayOutputStream();
        DataOutputStream c = new DataOutputStream(chainBody);
        c.write(2);                                 // entry type = KEY
        c.writeUTF("evil");
        c.writeLong(System.currentTimeMillis());
        c.writeInt(Integer.MAX_VALUE);              // poison chain length

        loadShouldRejectNotOOM("UBER", makeUberStore(blobBody.toByteArray(), password, salt, iterationCount), password);
        loadShouldRejectNotOOM("UBER", makeUberStore(chainBody.toByteArray(), password, salt, iterationCount), password);
    }

    private byte[] makeUberStore(byte[] body, char[] password, byte[] salt, int iterationCount)
        throws Exception
    {
        String alg = "PBEWithSHAAndTwofish-CBC";
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance(alg, "BC");
        Cipher cipher = Cipher.getInstance(alg, "BC");

        cipher.init(Cipher.ENCRYPT_MODE, keyFact.generateSecret(new PBEKeySpec(password)), new PBEParameterSpec(salt, iterationCount));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DataOutputStream dOut = new DataOutputStream(bOut);
        dOut.writeInt(2);                           // store version
        dOut.writeInt(salt.length);                 // salt length
        dOut.write(salt);                           // salt
        dOut.writeInt(iterationCount);              // iteration count
        dOut.write(cipher.doFinal(body));           // encrypted entries

        return bOut.toByteArray();
    }

    /*
     * A SEALED entry carries its own length-prefixed key salt, which is only parsed when the key
     * is recovered: an Integer.MAX_VALUE salt length there must surface as an
     * UnrecoverableKeyException rather than an OutOfMemoryError.
     */
    private void checkOversizedSealedSaltRejected()
        throws Exception
    {
        ByteArrayOutputStream sealedBlob = new ByteArrayOutputStream();
        DataOutputStream sb = new DataOutputStream(sealedBlob);
        sb.writeInt(Integer.MAX_VALUE);             // poison key salt length

        byte[] blob = sealedBlob.toByteArray();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt(2);                            // store version
        dos.writeInt(20);                           // salt length
        dos.write(new byte[20]);                    // salt
        dos.writeInt(1024);                         // iteration count
        dos.write(4);                               // entry type = SEALED
        dos.writeUTF("evil");                       // alias
        dos.writeLong(System.currentTimeMillis());  // creation date
        dos.writeInt(0);                            // chain length
        dos.writeInt(blob.length);                  // sealed blob length
        dos.write(blob);                            // sealed blob
        dos.write(0);                               // NULL entry terminator
        dos.write(new byte[20]);                    // store MAC (not checked for null password)

        KeyStore ks = KeyStore.getInstance("BKS", "BC");
        ks.load(new ByteArrayInputStream(baos.toByteArray()), null);

        isTrue("sealed entry not loaded", ks.isKeyEntry("evil"));

        try
        {
            ks.getKey("evil", "test".toCharArray());
            fail("oversized sealed key salt not rejected");
        }
        catch (UnrecoverableKeyException e)
        {
            // expected - the salt length is rejected before the array is allocated and read
        }
        catch (OutOfMemoryError e)
        {
            fail("oversized sealed key salt caused OutOfMemoryError");
        }
    }

    /*
     * An entry whose declared length genuinely exceeds the read buffer (and whose bytes are
     * actually present) must still load: the incremental read has to consume exactly the
     * declared number of bytes, otherwise the trailing store MAC would misalign and the load
     * would fail. Confirms the bounded-buffer hardening did not turn into a hard size cap.
     */
    private void checkLargeEntryStreamed()
        throws Exception
    {
        int bigLength = (2 * 1024 * 1024) + 1000;   // just over the 2 MiB read buffer

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt(2);                            // store version
        dos.writeInt(20);                           // salt length
        dos.write(new byte[20]);                    // salt
        dos.writeInt(1024);                         // iteration count
        dos.write(3);                               // entry type = SECRET
        dos.writeUTF("big");                        // alias
        dos.writeLong(System.currentTimeMillis());  // creation date
        dos.writeInt(0);                            // chain length
        dos.writeInt(bigLength);                    // blob length, > read buffer
        dos.write(new byte[bigLength]);             // the blob bytes really are present
        dos.write(0);                               // NULL entry terminator
        dos.write(new byte[20]);                    // store MAC (not checked for null password)

        KeyStore ks = KeyStore.getInstance("BKS", "BC");
        ks.load(new ByteArrayInputStream(baos.toByteArray()), null);

        isTrue("large entry not loaded", ks.containsAlias("big"));
        isTrue("unexpected entry count", ks.size() == 1);
    }

    /*
     * A crafted BKS/UBER stream declaring an enormous length-prefixed allocation must be
     * rejected with an IOException rather than driving an unbounded array allocation /
     * OutOfMemoryError before the integrity MAC is checked. The poison is reached regardless of
     * the password supplied, since loadStore() runs ahead of the MAC comparison.
     */
    private void checkOversizedEntryRejected()
        throws Exception
    {
        char[][] passwords = {null, new char[0], "test".toCharArray()};

        // BKS: a KEY entry with an Integer.MAX_VALUE certificate chain length.
        ByteArrayOutputStream chainPoison = new ByteArrayOutputStream();
        DataOutputStream c = new DataOutputStream(chainPoison);
        c.writeInt(2);                              // store version
        c.writeInt(20);                             // salt length
        c.write(new byte[20]);                      // salt
        c.writeInt(1024);                           // iteration count
        c.write(2);                                 // entry type = KEY
        c.writeUTF("evil");                         // alias
        c.writeLong(System.currentTimeMillis());    // creation date
        c.writeInt(Integer.MAX_VALUE);              // poison chain length

        // BKS: a SECRET entry (chain length 0) with an Integer.MAX_VALUE blob length.
        ByteArrayOutputStream blobPoison = new ByteArrayOutputStream();
        DataOutputStream b = new DataOutputStream(blobPoison);
        b.writeInt(2);
        b.writeInt(20);
        b.write(new byte[20]);
        b.writeInt(1024);
        b.write(3);                                 // entry type = SECRET
        b.writeUTF("evil");
        b.writeLong(System.currentTimeMillis());
        b.writeInt(0);                              // chain length
        b.writeInt(Integer.MAX_VALUE);              // poison blob length

        // BKS / UBER: an Integer.MAX_VALUE store salt length, read before any cipher is set up.
        ByteArrayOutputStream saltPoison = new ByteArrayOutputStream();
        DataOutputStream s = new DataOutputStream(saltPoison);
        s.writeInt(2);
        s.writeInt(Integer.MAX_VALUE);              // poison salt length

        for (int p = 0; p != passwords.length; p++)
        {
            loadShouldRejectNotOOM("BKS", chainPoison.toByteArray(), passwords[p]);
            loadShouldRejectNotOOM("BKS", blobPoison.toByteArray(), passwords[p]);
            loadShouldRejectNotOOM("BKS", saltPoison.toByteArray(), passwords[p]);
            loadShouldRejectNotOOM("UBER", saltPoison.toByteArray(), passwords[p]);
        }
    }

    private void loadShouldRejectNotOOM(String type, byte[] poison, char[] password)
        throws Exception
    {
        KeyStore ks = KeyStore.getInstance(type, "BC");
        try
        {
            ks.load(new ByteArrayInputStream(poison), password);
            fail("oversized " + type + " allocation not rejected");
        }
        catch (IOException e)
        {
            // expected - the length is rejected before the array is allocated and read
        }
        catch (OutOfMemoryError e)
        {
            fail("oversized " + type + " allocation caused OutOfMemoryError");
        }
    }

    public static void main(
        String[]    args)
    {
        System.setProperty("org.bouncycastle.bks.enable_v1", "true");

        Security.addProvider(new BouncyCastleProvider());

        runTest(new KeyStoreTest());
    }
}
