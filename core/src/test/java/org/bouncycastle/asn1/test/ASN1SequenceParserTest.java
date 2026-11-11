package org.bouncycastle.asn1.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Enumeration;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1ParsingException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.ASN1TaggedObjectParser;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.encoders.Hex;

public class ASN1SequenceParserTest 
    extends TestCase 
{
    private static final byte[] seqData = Hex.decode("3006020100060129");
    private static final byte[] nestedSeqData = Hex.decode("300b0201000601293003020101");
    private static final byte[] expTagSeqData = Hex.decode("a1083006020100060129");
    private static final byte[] implTagSeqData = Hex.decode("a106020100060129");
    private static final byte[] nestedSeqExpTagData = Hex.decode("300d020100060129a1053003020101");
    private static final byte[] nestedSeqImpTagData = Hex.decode("300b020100060129a103020101");
    
    private static final byte[] berSeqData = Hex.decode("30800201000601290000");
    private static final byte[] berDERNestedSeqData = Hex.decode("308002010006012930030201010000");
    private static final byte[] berNestedSeqData = Hex.decode("3080020100060129308002010100000000");
    private static final byte[] berExpTagSeqData = Hex.decode("a180308002010006012900000000");

    private static final byte[] berSeqWithDERNullData = Hex.decode("308005000201000601290000");

    public void testDERWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       DERSequenceGenerator  seqGen = new DERSequenceGenerator(bOut);
       
       seqGen.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen.addObject(new ASN1ObjectIdentifier("1.1"));
       
       seqGen.close();

       assertTrue("basic DER writing test failed.", Arrays.equals(seqData, bOut.toByteArray()));
    }
 
    public void testNestedDERWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       DERSequenceGenerator seqGen1 = new DERSequenceGenerator(bOut);
       
       seqGen1.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen1.addObject(new ASN1ObjectIdentifier("1.1"));
       
       DERSequenceGenerator seqGen2 = new DERSequenceGenerator(seqGen1.getRawOutputStream());
       
       seqGen2.addObject(new ASN1Integer(BigInteger.valueOf(1)));
       
       seqGen2.close();
       
       seqGen1.close();

       assertTrue("nested DER writing test failed.", Arrays.equals(nestedSeqData, bOut.toByteArray()));
    }

    public void testDERExplicitTaggedSequenceWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       DERSequenceGenerator  seqGen = new DERSequenceGenerator(bOut, 1, true);
       
       seqGen.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen.addObject(new ASN1ObjectIdentifier("1.1"));
       
       seqGen.close();

       assertTrue("explicit tag writing test failed.", Arrays.equals(expTagSeqData, bOut.toByteArray()));
    }
    
    public void testDERImplicitTaggedSequenceWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       DERSequenceGenerator  seqGen = new DERSequenceGenerator(bOut, 1, false);
       
       seqGen.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen.addObject(new ASN1ObjectIdentifier("1.1"));
       
       seqGen.close();

       assertTrue("implicit tag writing test failed.", Arrays.equals(implTagSeqData, bOut.toByteArray()));
    }
    
    public void testNestedExplicitTagDERWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       DERSequenceGenerator  seqGen1 = new DERSequenceGenerator(bOut);
       
       seqGen1.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen1.addObject(new ASN1ObjectIdentifier("1.1"));
       
       DERSequenceGenerator seqGen2 = new DERSequenceGenerator(seqGen1.getRawOutputStream(), 1, true);
       
       seqGen2.addObject(new ASN1Integer(BigInteger.valueOf(1)));
       
       seqGen2.close();
       
       seqGen1.close();

       assertTrue("nested explicit tagged DER writing test failed.", Arrays.equals(nestedSeqExpTagData, bOut.toByteArray()));
    }
    
    public void testNestedImplicitTagDERWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       DERSequenceGenerator  seqGen1 = new DERSequenceGenerator(bOut);
       
       seqGen1.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen1.addObject(new ASN1ObjectIdentifier("1.1"));
       
       DERSequenceGenerator seqGen2 = new DERSequenceGenerator(seqGen1.getRawOutputStream(), 1, false);
       
       seqGen2.addObject(new ASN1Integer(BigInteger.valueOf(1)));
       
       seqGen2.close();
       
       seqGen1.close();

       assertTrue("nested implicit tagged DER writing test failed.", Arrays.equals(nestedSeqImpTagData, bOut.toByteArray()));
    }
    
    public void testBERWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       BERSequenceGenerator  seqGen = new BERSequenceGenerator(bOut);
       
       seqGen.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen.addObject(new ASN1ObjectIdentifier("1.1"));
       
       seqGen.close();
       
       assertTrue("basic BER writing test failed.", Arrays.equals(berSeqData, bOut.toByteArray()));
    }

    public void testNestedBERDERWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       BERSequenceGenerator seqGen1 = new BERSequenceGenerator(bOut);
       
       seqGen1.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen1.addObject(new ASN1ObjectIdentifier("1.1"));
       
       DERSequenceGenerator seqGen2 = new DERSequenceGenerator(seqGen1.getRawOutputStream());
       
       seqGen2.addObject(new ASN1Integer(BigInteger.valueOf(1)));
       
       seqGen2.close();
       
       seqGen1.close();

       assertTrue("nested BER/DER writing test failed.", Arrays.equals(berDERNestedSeqData, bOut.toByteArray()));
    }
    
    public void testNestedBERWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       BERSequenceGenerator  seqGen1 = new BERSequenceGenerator(bOut);
       
       seqGen1.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen1.addObject(new ASN1ObjectIdentifier("1.1"));
       
       BERSequenceGenerator seqGen2 = new BERSequenceGenerator(seqGen1.getRawOutputStream());
       
       seqGen2.addObject(new ASN1Integer(BigInteger.valueOf(1)));
       
       seqGen2.close();
       
       seqGen1.close();

       assertTrue("nested BER writing test failed.", Arrays.equals(berNestedSeqData, bOut.toByteArray()));
    }
    
    public void testDERReading()
        throws Exception
    {
        ASN1StreamParser aIn = new ASN1StreamParser(seqData);
        
        ASN1SequenceParser    seq = (ASN1SequenceParser)aIn.readObject();
        Object          o;
        int             count = 0;
        
        assertNotNull("null sequence returned", seq);
        
        while ((o = seq.readObject()) != null)
        {
            switch (count)
            {
            case 0:
                assertTrue(o instanceof ASN1Integer);
                break;
            case 1:
                assertTrue(o instanceof ASN1ObjectIdentifier);
                break;
            }
            count++;
        }
        
        assertEquals("wrong number of objects in sequence", 2, count);
    }

    private void testNestedReading(
        byte[] data)
        throws Exception
    {
        ASN1StreamParser aIn = new ASN1StreamParser(data);
        
        ASN1SequenceParser seq = (ASN1SequenceParser)aIn.readObject();
        Object          o;
        int             count = 0;
        
        assertNotNull("null sequence returned", seq);
        
        while ((o = seq.readObject()) != null)
        {
            switch (count)
            {
            case 0:
                assertTrue(o instanceof ASN1Integer);
                break;
            case 1:
                assertTrue(o instanceof ASN1ObjectIdentifier);
                break;
            case 2:
                assertTrue(o instanceof ASN1SequenceParser);
                
                ASN1SequenceParser s = (ASN1SequenceParser)o;

                // NB: Must exhaust the nested parser
                while (s.readObject() != null)
                {
                    // Nothing
                }

                break;
            }
            count++;
        }
        
        assertEquals("wrong number of objects in sequence", 3, count);
    }
    
    public void testNestedDERReading()
        throws Exception
    {
        testNestedReading(nestedSeqData);
    }
    
    public void testBERReading()
        throws Exception
    {
        ASN1StreamParser aIn = new ASN1StreamParser(berSeqData);
        
        ASN1SequenceParser    seq = (ASN1SequenceParser)aIn.readObject();
        Object          o;
        int             count = 0;
        
        assertNotNull("null sequence returned", seq);
        
        while ((o = seq.readObject()) != null)
        {
            switch (count)
            {
            case 0:
                assertTrue(o instanceof ASN1Integer);
                break;
            case 1:
                assertTrue(o instanceof ASN1ObjectIdentifier);
                break;
            }
            count++;
        }
        
        assertEquals("wrong number of objects in sequence", 2, count);
    }
    
    public void testNestedBERDERReading()
        throws Exception
    {
        testNestedReading(berDERNestedSeqData);
    }
    
    public void testNestedBERReading()
        throws Exception
    {
        testNestedReading(berNestedSeqData);
    }
    
    public void testBERExplicitTaggedSequenceWriting()
        throws Exception
    {
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       BERSequenceGenerator  seqGen = new BERSequenceGenerator(bOut, 1, true);
       
       seqGen.addObject(new ASN1Integer(BigInteger.valueOf(0)));
       
       seqGen.addObject(new ASN1ObjectIdentifier("1.1"));
       
       seqGen.close();
      
       assertTrue("explicit BER tag writing test failed.", Arrays.equals(berExpTagSeqData, bOut.toByteArray()));
    }

    private static final String MAX_CONS_DEPTH_MESSAGE =
        "maximum nested construction level reached - increase org.bouncycastle.asn1.max_cons_depth (currently 64)";

    private static byte[] nestedDLSequence(int depth)
        throws IOException
    {
        ASN1Encodable node = new DERSequence();
        for (int i = 0; i < depth; i++)
        {
            node = new DERSequence(node);
        }
        return node.toASN1Primitive().getEncoded(ASN1Encoding.DER);
    }

    private static byte[] nestedILSequence(int depth)
    {
        // same shape as nestedDLSequence(depth), but every SEQUENCE uses the indefinite-length form
        int count = depth + 1;
        byte[] ber = new byte[count * 4];
        for (int i = 0; i < count; i++)
        {
            ber[2 * i] = 0x30;
            ber[2 * i + 1] = (byte)0x80;
        }
        // remaining bytes are the zero end-of-contents octets
        return ber;
    }

    public void testHeavilyDLNestedSequence()
        throws Exception
    {
        try
        {
            new ASN1InputStream(nestedDLSequence(256)).readObject();
            fail("no exception");
        }
        catch (IOException e)
        {
            assertEquals(MAX_CONS_DEPTH_MESSAGE, e.getMessage());
        }
    }

    public void testHeavilyBERNestedSequence()
        throws Exception
    {
        try
        {
            new ASN1InputStream(nestedILSequence(256)).readObject();
            fail("no exception");
        }
        catch (IOException e)
        {
            assertEquals(MAX_CONS_DEPTH_MESSAGE, e.getMessage());
        }
    }

    public void testHeavilyNestedSequenceStreamParser()
        throws Exception
    {
        try
        {
            ASN1SequenceParser seqParser = (ASN1SequenceParser)new ASN1StreamParser(nestedDLSequence(256)).readObject();
            seqParser.getLoadedObject();
            fail("no exception");
        }
        catch (IOException e)
        {
            assertEquals(MAX_CONS_DEPTH_MESSAGE, e.getMessage());
        }
    }

    public void testModeratelyNestedSequence()
        throws Exception
    {
        // nesting within the default max_cons_depth must still parse on every path
        byte[] der = nestedDLSequence(60);
        ASN1Primitive expected = ASN1Primitive.fromByteArray(der);

        assertTrue(Arrays.equals(der, expected.getEncoded(ASN1Encoding.DER)));

        ASN1Primitive lazy = new ASN1InputStream(der, true).readObject();
        assertEquals(expected.hashCode(), lazy.hashCode());
        assertEquals(expected, lazy);
        assertTrue(Arrays.equals(der, lazy.getEncoded(ASN1Encoding.DER)));

        ASN1Primitive ber = new ASN1InputStream(nestedILSequence(60)).readObject();
        assertTrue(Arrays.equals(der, ber.getEncoded(ASN1Encoding.DER)));
    }

    public void testHeavilyLazyNestedSequence()
        throws Exception
    {
        // Deeply nested SEQUENCE { SEQUENCE { ... } }, well past the default max_cons_depth (64)
        // but shallow enough that a whole-tree walk would not itself overflow the Java stack if the
        // guard were absent -- so this proves the guard is enforced, not merely that we crash.
        byte[] der = nestedDLSequence(256);

        // The lazy parse succeeds shallowly (only the outermost level is decoded eagerly).
        ASN1Primitive parsed = new ASN1InputStream(der, true).readObject();

        // Forcing the whole tree (hashCode walks every element) must hit the same nested-construction
        // limit the eager path enforces, raising an ASN1ParsingException rather than running the
        // whole 256-deep tree out and risking a StackOverflowError.
        try
        {
            parsed.hashCode();
            fail("nested construction depth limit not enforced on lazy parse");
        }
        catch (ASN1ParsingException e)
        {
            assertEquals(MAX_CONS_DEPTH_MESSAGE, e.getCause().getMessage());
        }
    }

    public void testHeavilyLazyNestedSequenceGetObjects()
        throws Exception
    {
        // Same crafted input, but walked through getObjects()/LazyConstructionEnumeration, the other
        // way a lazily captured SEQUENCE continues its deferred parse.
        byte[] der = nestedDLSequence(256);

        ASN1Sequence seq = (ASN1Sequence)new ASN1InputStream(der, true).readObject();

        try
        {
            for (int i = 0; i < 256; i++)
            {
                Enumeration en = seq.getObjects();
                assertTrue("sequence exhausted before depth limit reached", en.hasMoreElements());
                seq = (ASN1Sequence)en.nextElement();
            }
            fail("nested construction depth limit not enforced on lazy getObjects()");
        }
        catch (ASN1ParsingException e)
        {
            assertEquals(MAX_CONS_DEPTH_MESSAGE, e.getCause().getMessage());
        }
    }

    public void testHeavilyLazyNestedSequenceEqualsAndEncoding()
        throws Exception
    {
        // equals() and DER re-encoding (toDERObject()) also walk the whole lazily captured tree.
        byte[] der = nestedDLSequence(256);

        ASN1Primitive parsed = new ASN1InputStream(der, true).readObject();
        ASN1Primitive other = new ASN1InputStream(der, true).readObject();

        try
        {
            parsed.equals(other);
            fail("nested construction depth limit not enforced on lazy equals()");
        }
        catch (ASN1ParsingException e)
        {
            assertEquals(MAX_CONS_DEPTH_MESSAGE, e.getCause().getMessage());
        }

        parsed = new ASN1InputStream(der, true).readObject();
        try
        {
            parsed.getEncoded(ASN1Encoding.DER);
            fail("nested construction depth limit not enforced on lazy DER encoding");
        }
        catch (ASN1ParsingException e)
        {
            assertEquals(MAX_CONS_DEPTH_MESSAGE, e.getCause().getMessage());
        }
    }

    public void testHeavilyLazyNestedSequenceAndSet()
        throws Exception
    {
        // Alternate SEQUENCE (deferred by the lazy parse) and SET (always parsed eagerly) so the
        // nesting level has to be carried consistently across both paths.
        ASN1Encodable node = new DERSequence();
        for (int i = 0; i < 256; i++)
        {
            node = ((i & 1) == 0) ? (ASN1Encodable)new DERSet(node) : new DERSequence(node);
        }
        byte[] der = node.toASN1Primitive().getEncoded(ASN1Encoding.DER);

        ASN1Primitive parsed = new ASN1InputStream(der, true).readObject();

        try
        {
            parsed.hashCode();
            fail("nested construction depth limit not enforced on lazy parse");
        }
        catch (ASN1ParsingException e)
        {
            assertEquals(MAX_CONS_DEPTH_MESSAGE, e.getCause().getMessage());
        }
    }

    public void testHeavilyNestedExplicitTaggedObject()
        throws Exception
    {
        // [0] EXPLICIT { [0] EXPLICIT { ... SEQUENCE {} } } - nesting through constructed tagged
        // objects rather than SEQUENCE/SET must be bounded by the same limit on every parse path.
        ASN1Encodable node = new DERSequence();
        for (int i = 0; i < 256; i++)
        {
            node = new DERTaggedObject(true, 0, node);
        }
        byte[] der = node.toASN1Primitive().getEncoded(ASN1Encoding.DER);

        try
        {
            new ASN1InputStream(der).readObject();
            fail("nested construction depth limit not enforced on tagged objects");
        }
        catch (IOException e)
        {
            assertEquals(MAX_CONS_DEPTH_MESSAGE, e.getMessage());
        }

        try
        {
            new ASN1InputStream(der, true).readObject();
            fail("nested construction depth limit not enforced on lazily parsed tagged objects");
        }
        catch (IOException e)
        {
            assertEquals(MAX_CONS_DEPTH_MESSAGE, e.getMessage());
        }

        try
        {
            ASN1TaggedObjectParser tagParser = (ASN1TaggedObjectParser)new ASN1StreamParser(der).readObject();
            tagParser.getLoadedObject();
            fail("nested construction depth limit not enforced on stream-parsed tagged objects");
        }
        catch (IOException e)
        {
            assertEquals(MAX_CONS_DEPTH_MESSAGE, e.getMessage());
        }
    }

    public void testSequenceWithDERNullReading()
        throws Exception
    {
        testParseWithNull(berSeqWithDERNullData);
    }

    private void testParseWithNull(byte[] data)
        throws IOException
    {
        ASN1StreamParser aIn = new ASN1StreamParser(data);
        ASN1SequenceParser seq = (ASN1SequenceParser)aIn.readObject();
        Object          o;
        int             count = 0;

        assertNotNull("null sequence returned", seq);

        while ((o = seq.readObject()) != null)
        {
            switch (count)
            {
            case 0:
                assertTrue(o instanceof ASN1Null);
                break;
            case 1:
                assertTrue(o instanceof ASN1Integer);
                break;
            case 2:
                assertTrue(o instanceof ASN1ObjectIdentifier);
                break;
            }
            count++;
        }

        assertEquals("wrong number of objects in sequence", 3, count);
    }

    public static Test suite()
    {
        return new TestSuite(ASN1SequenceParserTest.class);
    }
}
