package org.bouncycastle.pqc.crypto.frodo;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;

/**
 * Regression tests for the constant-time hardening of the FrodoKEM implementation: the noise
 * sampler must no longer branch on the secret-derived comparison, and the Fujisaki-Okamoto
 * re-encryption check must no longer branch on whether it succeeded (the Guo-Johansson-Nilsson
 * key-recovery timing oracle).
 */
public class FrodoConstantTimeTest
    extends TestCase
{
    /**
     * The pre-hardening, data-dependent noise sampler, kept here verbatim as the reference the
     * branchless {@link Noise#sample(short[], short[], int, short[])} has to agree with.
     */
    private static short referenceSample(short[] tChi, short r)
    {
        short t, e;
        // 1. t = sum_{i=1}^{len_x - 1} r_i * 2^{i-1}
        t = (short)((r & 0xffff) >>> 1);
        e = 0; // 2. e = 0
        for (int z = 0; z < tChi.length; z++)
        {
            if (t > tChi[z]) // 4. if t > T_chi(z)
            {
                e++; // 5. e = e + 1
            }
        }
        // 6. e = (-1)^{r_0} * e
        if (((r & 0xffff) % 2) == 1)
        {
            e = (short)((e) * (-1) & 0xffff);
        }
        return e;
    }

    /**
     * Every CDF table shipped by {@link FrodoParameters}, collected reflectively so a table added
     * to a future parameter set is covered automatically.
     */
    private static List<short[]> cdfTables()
        throws Exception
    {
        List<short[]> tables = new ArrayList<short[]>();
        Field[] fields = FrodoParameters.class.getDeclaredFields();
        for (int i = 0; i != fields.length; i++)
        {
            Field f = fields[i];
            if (f.getType() == short[].class)
            {
                f.setAccessible(true);
                tables.add((short[])f.get(null));
            }
        }
        return tables;
    }

    /**
     * The branchy sampler {@code FrodoEngine.sample(short)} - whose {@code if (t > T_chi[z]) e++;}
     * was the leaking comparison - must be gone, with sampling routed through {@link Noise}
     * instead. Fails against the unpatched engine, where that method still exists.
     */
    public void testBranchyEngineSamplerIsGone()
        throws Exception
    {
        Method[] methods = FrodoEngine.class.getDeclaredMethods();
        for (int i = 0; i != methods.length; i++)
        {
            Class[] paramTypes = methods[i].getParameterTypes();
            if ("sample".equals(methods[i].getName())
                && paramTypes.length == 1 && paramTypes[0] == Short.TYPE)
            {
                fail("FrodoEngine still declares the data-dependent sample(short)");
            }
        }

        // ... and the constant-time replacement is what is there instead.
        Method sample = Noise.class.getDeclaredMethod("sample",
            new Class[]{short[].class, short[].class, Integer.TYPE, short[].class});
        assertTrue("Noise.sample must be static", java.lang.reflect.Modifier.isStatic(sample.getModifiers()));
    }

    public void testCdfTablesEndAtMaxSample()
        throws Exception
    {
        List<short[]> tables = cdfTables();

        assertEquals("expected one CDF table per FrodoKEM security level", 3, tables.size());

        // Noise.sample deliberately skips the final CDF entry ("no need to compare with the last
        // value"). That is only equivalent to the old sampler because prnd is at most 15 bits, so
        // it can never exceed a final entry of 0x7FFF.
        for (int i = 0; i != tables.size(); i++)
        {
            short[] cdf = (short[])tables.get(i);
            assertEquals("CDF table must end at 0x7FFF", (short)0x7FFF, cdf[cdf.length - 1]);
        }
    }

    /**
     * Exhaustive equivalence check: all 65536 pseudo-random 16-bit words, against every shipped
     * CDF table. Would catch an off-by-one in the {@code cdf.length - 1} bound, a wrong shift, or
     * broken sign handling.
     */
    public void testNoiseSampleMatchesDataDependentReference()
        throws Exception
    {
        List<short[]> tables = cdfTables();

        for (int t = 0; t != tables.size(); t++)
        {
            short[] cdf = (short[])tables.get(t);

            short[] r = new short[65536];
            for (int i = 0; i != r.length; i++)
            {
                r[i] = (short)i;
            }

            short[] expected = new short[r.length];
            for (int i = 0; i != r.length; i++)
            {
                expected[i] = referenceSample(cdf, r[i]);
            }

            short[] actual = new short[r.length];
            Noise.sample(cdf, r, 0, actual);

            for (int i = 0; i != r.length; i++)
            {
                assertEquals("cdf[" + t + "] r=" + (r[i] & 0xffff), expected[i], actual[i]);
            }

            // and again at a non-zero offset, since sample_matrix always calls it that way
            short[] shifted = new short[r.length - 7];
            Noise.sample(cdf, r, 7, shifted);
            for (int i = 0; i != shifted.length; i++)
            {
                assertEquals("offset cdf[" + t + "] i=" + i, expected[i + 7], shifted[i]);
            }
        }
    }

    /**
     * ctverify() no longer contains {@code if (r == 0) return 0; return -1;}. Check the branchless
     * replacement returns exactly the old values for every possible accumulator value.
     */
    public void testCtVerifyIsBranchlessAndPreservesPolarity()
        throws Exception
    {
        FrodoEngine engine = FrodoParameters.frodokem640aes.getEngine();

        Method ctverify = FrodoEngine.class.getDeclaredMethod("ctverify",
            new Class[]{short[].class, short[].class, short[].class, short[].class});
        ctverify.setAccessible(true);

        assertEquals("ctverify must still return a short so ctselect's masking stays correct",
            Short.TYPE, ctverify.getReturnType());

        short[] zero = new short[]{0};

        for (int v = 0; v != 65536; v++)
        {
            short[] a1 = new short[]{(short)v};
            short expected = (v == 0) ? (short)0 : (short)-1;

            Object r = ctverify.invoke(engine, new Object[]{a1, zero, zero, zero});
            assertEquals("ctverify a1 diff v=" + v, expected, ((Short)r).shortValue());

            // and via the second pair of arrays, which feeds the same accumulator
            r = ctverify.invoke(engine, new Object[]{zero, a1, zero, zero});
            assertEquals("ctverify a2 diff v=" + v, expected, ((Short)r).shortValue());
        }

        // multi-element arrays: a difference anywhere must be seen
        short[] eq1 = new short[]{1, 2, 3, 4};
        short[] eq2 = new short[]{5, 6, 7, 8};
        assertEquals((short)0, ((Short)ctverify.invoke(engine,
            new Object[]{eq1, eq2, Arrays.clone(eq1), Arrays.clone(eq2)})).shortValue());

        for (int i = 0; i != eq1.length; i++)
        {
            short[] bad = Arrays.clone(eq1);
            bad[i] = (short)(bad[i] ^ 0x8000);
            assertEquals("a1[" + i + "]", (short)-1, ((Short)ctverify.invoke(engine,
                new Object[]{eq1, eq2, bad, Arrays.clone(eq2)})).shortValue());

            short[] bad2 = Arrays.clone(eq2);
            bad2[i] = (short)(bad2[i] ^ 0x0001);
            assertEquals("a2[" + i + "]", (short)-1, ((Short)ctverify.invoke(engine,
                new Object[]{eq1, eq2, Arrays.clone(eq1), bad2})).shortValue());
        }
    }

    /**
     * The real security property, checked structurally rather than by timing (which is far too
     * noisy to assert in a unit test): after the accumulator loops, ctverify's bytecode must
     * contain no conditional jump at all. The vulnerable form ended in
     * {@code if (r == 0) return 0; return -1;}, which compiles to an ifne/ifeq, so this fails
     * against the unpatched engine and passes against the mask-based replacement.
     */
    public void testCtVerifyBytecodeHasNoSecretDependentBranch()
        throws Exception
    {
        byte[] classFile = readClassFile(FrodoEngine.class);
        byte[] code = extractMethodCode(classFile, "ctverify");

        assertNotNull("could not locate ctverify's Code attribute", code);

        // The two accumulator loops are the only legitimate control flow, and each branches on its
        // loop counter, not on the secret. So exactly two conditional jumps are expected; the
        // removed `if (r == 0) return 0; return -1;` compiled to a third one.
        List<String> conditional = conditionalBranchesIn(code);

        assertEquals("ctverify must branch only on its two loop counters, never on the accumulator "
            + "- found " + conditional, 2, conditional.size());

        // Both must be the counter-vs-length comparison; a branch on the accumulator would be a
        // compare-against-zero (ifeq/ifne) instead.
        for (int i = 0; i != conditional.size(); i++)
        {
            String op = (String)conditional.get(i);
            assertTrue("unexpected conditional branch " + op + " in ctverify",
                "if_icmpge".equals(op) || "if_icmplt".equals(op)
                    || "if_icmpgt".equals(op) || "if_icmple".equals(op));
        }
    }

    /**
     * Walks a Code attribute instruction by instruction (respecting operand lengths, so operand
     * bytes are never mistaken for opcodes) and names every conditional branch it contains.
     */
    private static List<String> conditionalBranchesIn(byte[] code)
    {
        List<String> found = new ArrayList<String>();

        for (int i = 0; i < code.length; )
        {
            int op = code[i] & 0xff;
            int operands;

            switch (op)
            {
            case 0xaa: // tableswitch
            {
                int p = (i + 4) & ~3; // skip to the 4-byte-aligned default offset
                int low = readInt(code, p + 4);
                int high = readInt(code, p + 8);
                operands = (p + 12 + (high - low + 1) * 4) - i - 1;
                break;
            }
            case 0xab: // lookupswitch
            {
                int p = (i + 4) & ~3;
                int npairs = readInt(code, p + 4);
                operands = (p + 8 + npairs * 8) - i - 1;
                break;
            }
            case 0xc4: // wide
                operands = ((code[i + 1] & 0xff) == 0x84) ? 5 : 3; // wide iinc vs wide load/store
                break;
            case 0x10: case 0x12: case 0x15: case 0x16: case 0x17: case 0x18: case 0x19:
            case 0x36: case 0x37: case 0x38: case 0x39: case 0x3a:
            case 0xa9: case 0xbc:
                operands = 1;
                break;
            case 0x11: case 0x13: case 0x14: case 0x84:
            case 0xb2: case 0xb3: case 0xb4: case 0xb5:
            case 0xb6: case 0xb7: case 0xb8:
            case 0xbb: case 0xbd: case 0xc0: case 0xc1:
                operands = 2;
                break;
            case 0xc5: // multianewarray
                operands = 3;
                break;
            case 0xb9: case 0xba: case 0xc8: case 0xc9: // invokeinterface, invokedynamic, goto_w, jsr_w
                operands = 4;
                break;
            default:
                if ((op >= 0x99 && op <= 0xa6) || op == 0xc6 || op == 0xc7)
                {
                    // ifeq..if_acmpne, ifnull, ifnonnull - all conditional, all 2 operand bytes
                    found.add(branchName(op));
                    operands = 2;
                }
                else if (op == 0xa7 || op == 0xa8) // goto, jsr - unconditional
                {
                    operands = 2;
                }
                else
                {
                    operands = 0;
                }
                break;
            }

            i += 1 + operands;
        }

        return found;
    }

    private static int readInt(byte[] b, int off)
    {
        return ((b[off] & 0xff) << 24) | ((b[off + 1] & 0xff) << 16)
            | ((b[off + 2] & 0xff) << 8) | (b[off + 3] & 0xff);
    }

    private static String branchName(int op)
    {
        String[] names = new String[]{
            "ifeq", "ifne", "iflt", "ifge", "ifgt", "ifle",
            "if_icmpeq", "if_icmpne", "if_icmplt", "if_icmpge", "if_icmpgt", "if_icmple",
            "if_acmpeq", "if_acmpne"};

        if (op >= 0x99 && op <= 0xa6)
        {
            return names[op - 0x99];
        }
        return op == 0xc6 ? "ifnull" : "ifnonnull";
    }

    private static byte[] readClassFile(Class clazz)
        throws Exception
    {
        java.io.InputStream in = clazz.getClassLoader().getResourceAsStream(
            clazz.getName().replace('.', '/') + ".class");
        assertNotNull("class file not found for " + clazz.getName(), in);
        try
        {
            java.io.ByteArrayOutputStream bOut = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int len;
            while ((len = in.read(buf)) >= 0)
            {
                bOut.write(buf, 0, len);
            }
            return bOut.toByteArray();
        }
        finally
        {
            in.close();
        }
    }

    /**
     * Minimal class-file walk: finds the named method and returns the bytes of its Code attribute.
     */
    private static byte[] extractMethodCode(byte[] cf, String methodName)
        throws Exception
    {
        java.io.DataInputStream in = new java.io.DataInputStream(new java.io.ByteArrayInputStream(cf));

        in.readInt();       // magic
        in.readUnsignedShort(); // minor
        in.readUnsignedShort(); // major

        int cpCount = in.readUnsignedShort();
        String[] utf8 = new String[cpCount];
        for (int i = 1; i < cpCount; i++)
        {
            int tag = in.readUnsignedByte();
            switch (tag)
            {
            case 1:  // Utf8
                utf8[i] = in.readUTF();
                break;
            case 7: case 8: case 16: case 19: case 20: // Class, String, MethodType, Module, Package
                in.skipBytes(2);
                break;
            case 15: // MethodHandle
                in.skipBytes(3);
                break;
            case 3: case 4: case 9: case 10: case 11: case 12: case 17: case 18:
                in.skipBytes(4);
                break;
            case 5: case 6: // Long, Double take two slots
                in.skipBytes(8);
                i++;
                break;
            default:
                throw new IllegalStateException("unexpected constant pool tag " + tag);
            }
        }

        in.skipBytes(2); // access flags
        in.skipBytes(2); // this class
        in.skipBytes(2); // super class
        int interfaces = in.readUnsignedShort();
        in.skipBytes(interfaces * 2);

        // fields
        int fieldCount = in.readUnsignedShort();
        for (int i = 0; i != fieldCount; i++)
        {
            in.skipBytes(6);
            skipAttributes(in);
        }

        // methods
        int methodCount = in.readUnsignedShort();
        for (int i = 0; i != methodCount; i++)
        {
            in.skipBytes(2); // access flags
            String name = utf8[in.readUnsignedShort()];
            in.skipBytes(2); // descriptor

            int attrCount = in.readUnsignedShort();
            for (int a = 0; a != attrCount; a++)
            {
                String attrName = utf8[in.readUnsignedShort()];
                int attrLen = in.readInt();
                if (methodName.equals(name) && "Code".equals(attrName))
                {
                    in.skipBytes(4); // max_stack, max_locals
                    int codeLen = in.readInt();
                    byte[] code = new byte[codeLen];
                    in.readFully(code);
                    return code;
                }
                in.skipBytes(attrLen);
            }
        }
        return null;
    }

    private static void skipAttributes(java.io.DataInputStream in)
        throws Exception
    {
        int attrCount = in.readUnsignedShort();
        for (int a = 0; a != attrCount; a++)
        {
            in.skipBytes(2);
            in.skipBytes(in.readInt());
        }
    }

    /**
     * End-to-end proof that the branchless ctverify is wired up with the right polarity: a valid
     * ciphertext must still decapsulate to the encapsulated secret, and a corrupted one must
     * silently produce the implicit-rejection value SHAKE(c1 || c2 || s) - not throw, and not leak
     * which of the two branches was taken.
     */
    public void testKemDecImplicitRejection()
    {
        // 640 covers both matrix generators, 976shake covers the larger SHAKE-256 / B=3 branch.
        // frodokem1344 is left to FrodoVectorTest's KATs: at n=1344 a key pair plus eight
        // decapsulations here would dominate the suite's runtime for no extra coverage of the
        // ctverify call site.
        FrodoParameters[] params = new FrodoParameters[]{
            FrodoParameters.frodokem640aes,
            FrodoParameters.frodokem640shake,
            FrodoParameters.frodokem976shake
        };
        int[] shakeSizes = new int[]{128, 128, 256};

        SecureRandom random = new SecureRandom();

        for (int p = 0; p != params.length; p++)
        {
            FrodoParameters parameters = params[p];

            FrodoKeyPairGenerator kpGen = new FrodoKeyPairGenerator();
            kpGen.init(new FrodoKeyGenerationParameters(random, parameters));
            AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

            FrodoPublicKeyParameters pub = (FrodoPublicKeyParameters)kp.getPublic();
            FrodoPrivateKeyParameters priv = (FrodoPrivateKeyParameters)kp.getPrivate();

            SecretWithEncapsulation enc = new FrodoKEMGenerator(random).generateEncapsulated(pub);
            byte[] ct = enc.getEncapsulation();
            byte[] ss = enc.getSecret();

            FrodoKEMExtractor extractor = new FrodoKEMExtractor(priv);

            // the honest path still agrees
            assertTrue(parameters.getName() + ": honest decapsulation",
                Arrays.areEqual(ss, extractor.extractSecret(ct)));

            int ssLen = parameters.getSessionKeySize() / 8;
            byte[] s = Arrays.copyOfRange(priv.getPrivateKey(), 0, ssLen);

            // corrupt the ciphertext in c1 and in c2
            int[] positions = new int[]{0, ct.length / 2, ct.length - 1};
            for (int i = 0; i != positions.length; i++)
            {
                byte[] badCt = Arrays.clone(ct);
                badCt[positions[i]] ^= 0x01;

                byte[] rejected = extractor.extractSecret(badCt);

                assertEquals(parameters.getName() + ": rejection length", ssLen, rejected.length);
                assertFalse(parameters.getName() + ": rejection must not equal the real secret",
                    Arrays.areEqual(ss, rejected));

                // 17. ss = SHAKE(c1 || c2 || kbar) with kbar == s, i.e. the ctverify branch was
                // taken as "not equal" and ctselect picked s over k'.
                byte[] expected = new byte[ssLen];
                Xof shake = new SHAKEDigest(shakeSizes[p]);
                shake.update(badCt, 0, badCt.length);
                shake.update(s, 0, s.length);
                shake.doFinal(expected, 0, expected.length);

                assertTrue(parameters.getName() + ": implicit rejection value at " + positions[i],
                    Arrays.areEqual(expected, rejected));

                // deterministic, so no branch-dependent state leaked between calls
                assertTrue(parameters.getName() + ": rejection is deterministic",
                    Arrays.areEqual(rejected, extractor.extractSecret(badCt)));
            }

            // and the honest path still works after the rejections
            assertTrue(parameters.getName() + ": honest decapsulation after rejection",
                Arrays.areEqual(ss, extractor.extractSecret(ct)));
        }
    }
}
