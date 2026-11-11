package org.bouncycastle.asn1.test;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1BMPString;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OctetStringParser;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DEROctetStringParser;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Regression coverage for the definite-length materialization allocation guard in
 * {@code DefiniteLengthInputStream.toByteArray()}. When {@code ASN1InputStream} wraps a raw
 * (non-array, non-file) stream, the per-object limit falls back to {@code Runtime.maxMemory}
 * ({@code StreamUtil.findLimit}), so allocating the full declared length up front let a short
 * crafted header - an OCTET STRING declaring a near-heap length with no body - drive an
 * OutOfMemoryError before any data was read (CWE-789). The buffer is now grown as bytes actually
 * arrive: a short input allocates only a bounded working buffer, a well-formed object still
 * materializes correctly, and a truncated object still fails with the established
 * "DEF length ... object truncated by ..." EOFException.
 */
public class DefiniteLengthAllocationTest
    extends SimpleTest
{
    public String getName()
    {
        return "DefiniteLengthAllocation";
    }

    public void performTest()
        throws Exception
    {
        testDeclaredLengthNotAllocatedUpFront();
        testTruncatedObjectReportsExpectedMessage();
        testHostileOctetStringLength();
        testHostileBMPStringLength();
        testHostileTaggedPrimitiveLength();
        testHostileLazySequenceLength();
        testHostileStreamParserOctetStringLength();
        testBMPStringRoundTrip();
    }

    /**
     * The largest definite length ASN1InputStream / ASN1StreamParser accept for a raw (non-array,
     * non-file) stream: StreamUtil.findLimit falls back to Runtime.maxMemory, and a length must be
     * strictly below that limit.
     */
    private static int hostileLength()
    {
        long maxMemory = Runtime.getRuntime().maxMemory();
        int limit = (maxMemory > Integer.MAX_VALUE) ? Integer.MAX_VALUE : (int)maxMemory;
        return (limit - 1) & ~1;    // even, so it is also a well-formed BMPString length
    }

    /**
     * A header with the given identifier octet and a 4-octet long-form definite length, followed by
     * only {@code bodySupplied} content octets.
     */
    private static byte[] hostileEncoding(int tag, int declaredLength, int bodySupplied)
    {
        byte[] input = new byte[6 + bodySupplied];
        input[0] = (byte)tag;
        input[1] = (byte)0x84;          // long form, 4 length octets
        input[2] = (byte)(declaredLength >>> 24);
        input[3] = (byte)(declaredLength >>> 16);
        input[4] = (byte)(declaredLength >>> 8);
        input[5] = (byte)declaredLength;
        for (int i = 6; i < input.length; ++i)
        {
            input[i] = (byte)0x41;
        }
        return input;
    }

    private void checkHostileTruncation(String label, EOFException e, int declaredLength, int bodySupplied,
        RecordingStream in)
    {
        String expected = "DEF length " + declaredLength + " object truncated by " + (declaredLength - bodySupplied);
        isTrue(label + ": unexpected truncation message: " + e.getMessage(), expected.equals(e.getMessage()));
        isTrue(label + ": first bulk read requested the full declared length (" + in.firstBulkReadLength + ")",
            in.firstBulkReadLength >= 0 && in.firstBulkReadLength < declaredLength);
    }

    /**
     * Exploit: a 16-byte OCTET STRING declaring a near-heap length over a raw stream. Before the fix
     * this allocated new byte[length] up front and failed with OutOfMemoryError; it must now fail with
     * the truncation EOFException having allocated only a bounded working buffer.
     */
    private void testHostileOctetStringLength()
        throws IOException
    {
        int declaredLength = hostileLength();
        int bodySupplied = 10;
        RecordingStream in = new RecordingStream(hostileEncoding(0x04, declaredLength, bodySupplied));
        try
        {
            new ASN1InputStream(in).readObject();
            fail("no exception on hostile OCTET STRING length");
        }
        catch (EOFException e)
        {
            checkHostileTruncation("OCTET STRING", e, declaredLength, bodySupplied, in);
        }
    }

    /**
     * Exploit: a BMPString declaring a near-heap length over a raw stream. Before the fix this
     * allocated new char[length / 2] (i.e. length bytes of heap) before reading any content.
     */
    private void testHostileBMPStringLength()
        throws IOException
    {
        int declaredLength = hostileLength();
        int bodySupplied = 10;
        RecordingStream in = new RecordingStream(hostileEncoding(0x1E, declaredLength, bodySupplied));
        try
        {
            new ASN1InputStream(in).readObject();
            fail("no exception on hostile BMPString length");
        }
        catch (EOFException e)
        {
            String expected = "DEF length " + declaredLength + " object truncated by " + (declaredLength - bodySupplied);
            isTrue("BMPString: unexpected truncation message: " + e.getMessage(), expected.equals(e.getMessage()));
        }
    }

    /**
     * Exploit: a primitive context-specific tagged object ([0] IMPLICIT) declaring a near-heap length.
     */
    private void testHostileTaggedPrimitiveLength()
        throws IOException
    {
        int declaredLength = hostileLength();
        int bodySupplied = 10;
        RecordingStream in = new RecordingStream(hostileEncoding(0x80, declaredLength, bodySupplied));
        try
        {
            new ASN1InputStream(in).readObject();
            fail("no exception on hostile tagged primitive length");
        }
        catch (EOFException e)
        {
            checkHostileTruncation("tagged primitive", e, declaredLength, bodySupplied, in);
        }
    }

    /**
     * Exploit: a SEQUENCE declaring a near-heap length read with lazy evaluation, whose contents are
     * captured whole via toByteArray().
     */
    private void testHostileLazySequenceLength()
        throws IOException
    {
        int declaredLength = hostileLength();
        int bodySupplied = 10;
        RecordingStream in = new RecordingStream(hostileEncoding(0x30, declaredLength, bodySupplied));
        try
        {
            new ASN1InputStream(in, true).readObject();
            fail("no exception on hostile lazy SEQUENCE length");
        }
        catch (EOFException e)
        {
            checkHostileTruncation("lazy SEQUENCE", e, declaredLength, bodySupplied, in);
        }
    }

    /**
     * Exploit: the streaming parser materializing a primitive OCTET STRING declaring a near-heap
     * length (DEROctetStringParser.getLoadedObject()).
     */
    private void testHostileStreamParserOctetStringLength()
        throws IOException
    {
        int declaredLength = hostileLength();
        int bodySupplied = 10;
        RecordingStream in = new RecordingStream(hostileEncoding(0x04, declaredLength, bodySupplied));
        try
        {
            ASN1OctetStringParser parser = (ASN1OctetStringParser)new ASN1StreamParser(in).readObject();
            isTrue("unexpected parser type: " + parser.getClass(), parser instanceof DEROctetStringParser);
            parser.getLoadedObject();
            fail("no exception on hostile stream-parser OCTET STRING length");
        }
        catch (EOFException e)
        {
            checkHostileTruncation("stream parser OCTET STRING", e, declaredLength, bodySupplied, in);
        }
    }

    /**
     * A well-formed BMPString (spanning several internal read chunks) still decodes correctly, and an
     * odd content length is still rejected, now that its contents are materialized via toByteArray().
     */
    private void testBMPStringRoundTrip()
        throws IOException
    {
        char[] chars = new char[5000];
        for (int i = 0; i != chars.length; i++)
        {
            chars[i] = (char)(0x20 + (i * 31) % 0xD000);
        }
        String value = new String(chars);
        byte[] encoding = new DERBMPString(value).getEncoded();

        ASN1BMPString decoded = (ASN1BMPString)new ASN1InputStream(new RecordingStream(encoding)).readObject();
        isTrue("BMPString did not round trip", value.equals(decoded.getString()));

        ASN1BMPString empty = (ASN1BMPString)new ASN1InputStream(new RecordingStream(new byte[]{ 0x1E, 0x00 })).readObject();
        isTrue("empty BMPString did not round trip", "".equals(empty.getString()));

        try
        {
            new ASN1InputStream(new RecordingStream(new byte[]{ 0x1E, 0x03, 0x00, 0x41, 0x00 })).readObject();
            fail("no exception on odd-length BMPString");
        }
        catch (IOException e)
        {
            isTrue("unexpected message: " + e.getMessage(), "malformed BMPString encoding encountered".equals(e.getMessage()));
        }
    }

    /**
     * A large declared length must not be requested (and therefore allocated) in a single up-front
     * read: the eager {@code new byte[length]} asked the stream for the whole declared length at
     * once, whereas the guard reads into a bounded, incrementally grown buffer.
     */
    private void testDeclaredLengthNotAllocatedUpFront()
        throws IOException
    {
        int declaredLength = 1 << 20;   // 1 MiB - comfortably past the bounded working buffer

        // OCTET STRING (tag 0x04), long-form length 0x100000, followed by a full body.
        byte[] input = new byte[5 + declaredLength];
        input[0] = (byte)0x04;
        input[1] = (byte)0x83;          // long form, 3 length octets
        input[2] = (byte)0x10;
        input[3] = (byte)0x00;
        input[4] = (byte)0x00;

        RecordingStream in = new RecordingStream(input);
        ASN1OctetString octets = (ASN1OctetString)new ASN1InputStream(in).readObject();

        isTrue("octet string did not materialize to the declared length",
            octets.getOctets().length == declaredLength);
        isTrue("first bulk read requested the full declared length (" + in.firstBulkReadLength + ")",
            in.firstBulkReadLength >= 0 && in.firstBulkReadLength < declaredLength);
    }

    /**
     * A definite-length object whose stream ends early still fails with the exact truncation
     * message the eager read produced (the message text is asserted elsewhere in the suite).
     */
    private void testTruncatedObjectReportsExpectedMessage()
    {
        int declaredLength = 1 << 20;
        int bodySupplied = 10;

        byte[] input = new byte[5 + bodySupplied];
        input[0] = (byte)0x04;
        input[1] = (byte)0x83;
        input[2] = (byte)0x10;
        input[3] = (byte)0x00;
        input[4] = (byte)0x00;

        try
        {
            new ASN1InputStream(new RecordingStream(input)).readObject();
            fail("no exception on truncated definite-length object");
        }
        catch (EOFException e)
        {
            String expected = "DEF length " + declaredLength + " object truncated by " + (declaredLength - bodySupplied);
            isTrue("unexpected truncation message: " + e.getMessage(), expected.equals(e.getMessage()));
        }
        catch (IOException e)
        {
            fail("unexpected exception: " + e);
        }
    }

    /**
     * A generic InputStream (so StreamUtil.findLimit takes the Runtime.maxMemory fallback) that
     * records the size of the first bulk read(byte[], int, int) request.
     */
    private static final class RecordingStream
        extends InputStream
    {
        private final byte[] data;
        private int pos = 0;
        int firstBulkReadLength = -1;

        RecordingStream(byte[] data)
        {
            this.data = data;
        }

        public int read()
        {
            return pos < data.length ? (data[pos++] & 0xFF) : -1;
        }

        public int read(byte[] buf, int off, int len)
        {
            if (firstBulkReadLength < 0)
            {
                firstBulkReadLength = len;
            }
            if (pos >= data.length)
            {
                return -1;
            }
            int n = Math.min(len, data.length - pos);
            System.arraycopy(data, pos, buf, off, n);
            pos += n;
            return n;
        }
    }

    public static void main(String[] args)
    {
        runTest(new DefiniteLengthAllocationTest());
    }
}
