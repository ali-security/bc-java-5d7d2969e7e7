package org.bouncycastle.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ParsingException;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * A CRL whose revokedCertificates field is a deeply nested SEQUENCE { SEQUENCE { ... } } is
 * captured lazily by the BC CertificateFactory. Walking it later (hashCode(), equals(), DER
 * re-encoding for getEncoded()/getTBSCertList()/verify()) must stop at the ASN.1 nested-construction
 * limit instead of recursing once per level until the stack overflows.
 */
public class CRLNestingDepthTest
    extends TestCase
{
    private static final String BC = "BC";

    private static final String MAX_CONS_DEPTH_MESSAGE =
        "maximum nested construction level reached - increase org.bouncycastle.asn1.max_cons_depth (currently 64)";

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testDeeplyNestedRevokedCertificates()
        throws Exception
    {
        // ~10,000 levels in ~40KB, the shape of the crafted CRL described for CVE-2026-13506
        byte[] crlEncoding = createCRL(10000);

        CertificateFactory cf = CertificateFactory.getInstance("X.509", BC);

        // parsing is shallow (lazy) and succeeds
        X509CRL crl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(crlEncoding));
        X509CRL other = (X509CRL)cf.generateCRL(new ByteArrayInputStream(crlEncoding));

        try
        {
            crl.hashCode();
            fail("nested construction depth limit not enforced on CRL hashCode()");
        }
        catch (ASN1ParsingException e)
        {
            assertEquals(MAX_CONS_DEPTH_MESSAGE, e.getCause().getMessage());
        }
        catch (StackOverflowError e)
        {
            fail("stack overflow walking nested CRL in hashCode()");
        }

        try
        {
            crl.getTBSCertList();
            fail("nested construction depth limit not enforced on CRL getTBSCertList()");
        }
        catch (ASN1ParsingException e)
        {
            assertEquals(MAX_CONS_DEPTH_MESSAGE, e.getCause().getMessage());
        }
        catch (StackOverflowError e)
        {
            fail("stack overflow walking nested CRL in getTBSCertList()");
        }

        try
        {
            other.getEncoded();
            fail("nested construction depth limit not enforced on CRL getEncoded()");
        }
        catch (ASN1ParsingException e)
        {
            assertEquals(MAX_CONS_DEPTH_MESSAGE, e.getCause().getMessage());
        }
        catch (StackOverflowError e)
        {
            fail("stack overflow walking nested CRL in getEncoded()");
        }
    }

    public void testModeratelyNestedRevokedCertificates()
        throws Exception
    {
        // nesting within the limit is still processed normally
        byte[] crlEncoding = createCRL(40);

        CertificateFactory cf = CertificateFactory.getInstance("X.509", BC);

        X509CRL crl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(crlEncoding));
        X509CRL other = (X509CRL)cf.generateCRL(new ByteArrayInputStream(crlEncoding));

        assertEquals(crl.hashCode(), other.hashCode());
        assertEquals(crl, other);
        assertTrue(org.bouncycastle.util.Arrays.areEqual(crlEncoding, crl.getEncoded()));
    }

    private static byte[] createCRL(int depth)
        throws IOException
    {
        AlgorithmIdentifier sigAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE);

        byte[] nested = createNestedSequence(depth);

        ByteArrayOutputStream tbs = new ByteArrayOutputStream();
        tbs.write(new ASN1Integer(1).getEncoded(ASN1Encoding.DER));
        tbs.write(sigAlg.getEncoded(ASN1Encoding.DER));
        tbs.write(new X500Name("CN=Nested CRL Test").getEncoded(ASN1Encoding.DER));
        tbs.write(new ASN1UTCTime("260101000000Z").getEncoded(ASN1Encoding.DER));
        tbs.write(nested);

        ByteArrayOutputStream crl = new ByteArrayOutputStream();
        crl.write(encodeSequence(tbs.toByteArray()));
        crl.write(sigAlg.getEncoded(ASN1Encoding.DER));
        crl.write(new DERBitString(new byte[256]).getEncoded(ASN1Encoding.DER));

        return encodeSequence(crl.toByteArray());
    }

    /**
     * DER encoding of depth SEQUENCEs nested inside each other, the innermost one empty.
     */
    private static byte[] createNestedSequence(int depth)
    {
        // contentLengths[i] is the contents length of the i-th SEQUENCE counting from the outside
        int[] contentLengths = new int[depth];
        int encodedLength = 0;
        for (int i = depth - 1; i >= 0; i--)
        {
            contentLengths[i] = encodedLength;
            encodedLength = 1 + lengthOfLength(encodedLength) + encodedLength;
        }

        byte[] encoding = new byte[encodedLength];
        int pos = 0;
        for (int i = 0; i < depth; i++)
        {
            encoding[pos++] = 0x30;
            pos = writeLength(encoding, pos, contentLengths[i]);
        }

        return encoding;
    }

    private static byte[] encodeSequence(byte[] contents)
    {
        byte[] encoding = new byte[1 + lengthOfLength(contents.length) + contents.length];

        encoding[0] = 0x30;
        int pos = writeLength(encoding, 1, contents.length);
        System.arraycopy(contents, 0, encoding, pos, contents.length);

        return encoding;
    }

    private static int lengthOfLength(int length)
    {
        int size = 1;
        if (length >= 128)
        {
            for (int val = length; val != 0; val >>>= 8)
            {
                size++;
            }
        }
        return size;
    }

    private static int writeLength(byte[] buf, int pos, int length)
    {
        if (length < 128)
        {
            buf[pos++] = (byte)length;
            return pos;
        }

        int size = lengthOfLength(length) - 1;
        buf[pos++] = (byte)(0x80 | size);
        for (int i = (size - 1) * 8; i >= 0; i -= 8)
        {
            buf[pos++] = (byte)(length >> i);
        }
        return pos;
    }
}
