package org.bouncycastle.jce.provider.test;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.OtherName;
import org.bouncycastle.jce.provider.PKIXNameConstraintValidator;
import org.bouncycastle.jce.provider.PKIXNameConstraintValidatorException;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Test class for {@link PKIXNameConstraintValidator}.
 * <p>
 * The field testXYZ is the name to test.
 * <p>
 * The field testXYZIsConstraint must be tested if it is permitted and excluded.
 * <p>
 * The field testXYZIsNotConstraint must be tested if it is not permitted and
 * not excluded.
 * <p>
 * Furthermore there are tests for the intersection and union of test names.
 * 
 */
public class PKIXNameConstraintsTest
    extends SimpleTest
{

    private final static String testEmail = "test@abc.test.com";

    private final static String testEmailIsConstraint[] =
    { "test@abc.test.com", "abc.test.com", ".test.com" };

    private final static String testEmailIsNotConstraint[] =
    { ".abc.test.com", "www.test.com", "test1@abc.test.com", "bc.test.com" };

    private final static String email1[] =
    { "test@test.com", "test@test.com", "test@test.com", "test@abc.test.com",
            "test@test.com", "test@test.com", ".test.com", ".test.com",
            ".test.com", ".test.com", "test.com", "abc.test.com",
            "abc.test1.com", "test.com", "test.com", ".test.com" };

    private final static String email2[] =
    { "test@test.abc.com", "test@test.com", ".test.com", ".test.com",
            "test.com", "test1.com", "test@test.com", ".test.com",
            ".test1.com", "test.com", "test.com", ".test.com", ".test.com",
            "test1.com", ".test.com", "abc.test.com" };

    private final static String emailintersect[] =
    { null, "test@test.com", null, "test@abc.test.com", "test@test.com", null,
            null, ".test.com", null, null, "test.com", "abc.test.com", null,
            null, null, "abc.test.com" };

    private final static String emailunion[][] =
    {
    { "test@test.com", "test@test.abc.com" },
    { "test@test.com" },
    { "test@test.com", ".test.com" },
    { ".test.com" },
    { "test.com" },
    { "test@test.com", "test1.com" },
    { ".test.com", "test@test.com" },
    { ".test.com" },
    { ".test.com", ".test1.com" },
    { ".test.com", "test.com" },
    { "test.com" },
    { ".test.com" },
    { ".test.com", "abc.test1.com" },
    { "test1.com", "test.com" },
    { ".test.com", "test.com" },
    { ".test.com" } };

    private final static String[] dn1 =
    { "O=test org, OU=test org unit, CN=John Doe" };

    private final static String[] dn2 =
    { "O=test org, OU=test org unit" };

    private final static String[][] dnUnion =
    {
    { "O=test org, OU=test org unit" } };

    private final static String[] dnIntersection =
    { "O=test org, OU=test org unit, CN=John Doe" };

    // Note: In BC text conversion is ISO format - IETF starts at the back.
    private final static String testDN = "O=test org, OU=test org unit, CN=John Doe";

    private final static String testDNIsConstraint[] =
    {
        "O=test org, OU=test org unit",
        "O=test org, OU=test org unit, CN=John Doe",
    };

    private final static String testDNIsNotConstraint[] =
    {
        "O=test org, OU=test org unit, CN=John Doe2",
        "O=test org, OU=test org unit2",
        "O=test org, OU=test org unit, CN=John Doe, L=USA"
    };

    private final static String testDNS = "abc.test.com";

    private final static String testDNSIsConstraint[] =
    { "test.com", "abc.test.com", "test.com" };

    private final static String testDNSIsNotConstraint[] =
    { "wwww.test.com", "ww.test.com", "www.test.com" };

    private final static String dns1[] =
    { "www.test.de", "www.test1.de", "www.test.de" };

    private final static String dns2[] =
    { "test.de", "www.test.de", "www.test.de" };

    private final static String dnsintersect[] =
    { "www.test.de", null, null };

    private final static String dnsunion[][] =
    {
    { "test.de" },
    { "www.test1.de", "www.test.de" },
    { "www.test.de" } };

    private final static String testURI = "http://karsten:password@abc.test.com:8080";

    private final static String testURIIsConstraint[] =
    { "abc.test.com", ".test.com" };

    private final static String testURIIsNotConstraint[] =
    { "xyz.test.com", ".abc.test.com" };

    private final static String uri1[] =
    { "www.test.de", ".test.de", "test1.de", ".test.de" };

    private final static String uri2[] =
    { "test.de", "www.test.de", "test1.de", ".test.de" };

    private final static String uriintersect[] =
    { null, "www.test.de", "test1.de", ".test.de" };

    private final static String uriunion[][] =
    {
    { "www.test.de", "test.de" },
    { ".test.de" },
    { "test1.de" },
    { ".test.de" } };

    private final static byte[] testIP =

    { (byte) 192, (byte) 168, 1, 2 };

    private final static byte[][] testIPIsConstraint =
    {
    { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0 },
    { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 4 } };

    private final static byte[][] testIPIsNotConstraint =
    {
    { (byte) 192, (byte) 168, 3, 1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 2 },
    { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 3 } };

    private final static byte[][] ip1 =
    {
            { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFE, (byte) 0xFF },
            { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0xFF },
            { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0x00 } };

    private final static byte[][] ip2 =
    {
            { (byte) 192, (byte) 168, 0, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFC, 3 },
            { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0xFF },
            { (byte) 192, (byte) 168, 0, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0x00 } };

    private final static byte[][] ipintersect =
    {
            { (byte) 192, (byte) 168, 0, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFE, (byte) 0xFF },
            { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0xFF }, null };

    private final static byte[][][] ipunion =
    {
            {
                    { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                            (byte) 0xFE, (byte) 0xFF },
                    { (byte) 192, (byte) 168, 0, 1, (byte) 0xFF, (byte) 0xFF,
                            (byte) 0xFC, 3 } },
            {
            { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0xFF } },
            {
                    { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                            (byte) 0xFF, (byte) 0x00 },
                    { (byte) 192, (byte) 168, 0, 1, (byte) 0xFF, (byte) 0xFF,
                            (byte) 0xFF, (byte) 0x00 } } };

    public String getName()
    {
        return "PKIXNameConstraintsTest";
    }

    public void performTest() throws Exception
    {
        testConstraints(GeneralName.rfc822Name, testEmail,
            testEmailIsConstraint, testEmailIsNotConstraint, email1, email2,
            emailunion, emailintersect);
        testConstraints(GeneralName.dNSName, testDNS, testDNSIsConstraint,
            testDNSIsNotConstraint, dns1, dns2, dnsunion, dnsintersect);
        testConstraints(GeneralName.directoryName, testDN, testDNIsConstraint,
            testDNIsNotConstraint, dn1, dn2, dnUnion, dnIntersection);
        testConstraints(GeneralName.uniformResourceIdentifier, testURI,
            testURIIsConstraint, testURIIsNotConstraint, uri1, uri2, uriunion,
            uriintersect);
        testConstraints(GeneralName.iPAddress, testIP, testIPIsConstraint,
            testIPIsNotConstraint, ip1, ip2, ipunion, ipintersect);

        PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
        constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
            new GeneralName(GeneralName.directoryName, new X500Name(RFC4519Style.INSTANCE, "ou=permittedSubtree1, o=Test Certificates 2011, c=US"))));
        constraintValidator.checkPermitted(new GeneralName(GeneralName.directoryName, new X500Name(RFC4519Style.INSTANCE, "cn=Valid DN nameConstraints EE Certificate Test1, ou=permittedSubtree1, o=Test Certificates 2011, c=US")));

        GeneralName name = new GeneralName(GeneralName.otherName, new OtherName(new ASN1ObjectIdentifier("1.1"), DERNull.INSTANCE));
        GeneralSubtree subtree = new GeneralSubtree(name);

        PKIXNameConstraintValidator validator = new PKIXNameConstraintValidator();
        validator.intersectPermittedSubtree(subtree);

        name = new GeneralName(GeneralName.otherName, new OtherName(new ASN1ObjectIdentifier("1.1"), DERNull.INSTANCE));
        subtree = new GeneralSubtree(name);

        validator = new PKIXNameConstraintValidator();
        validator.intersectPermittedSubtree(subtree);
        validator.addExcludedSubtree(subtree);

        try
        {
            validator.checkExcluded(name);
        }
        catch (PKIXNameConstraintValidatorException e)
        {
            isEquals("OtherName is from an excluded subtree.", e.getMessage());
        }

        try
        {
            validator.checkPermitted(name);
        }
        catch (PKIXNameConstraintValidatorException e)
        {
            fail(e.getMessage());
        }

        testNameConstraintBypasses();
    }

    private void testNameConstraintBypasses()
        throws Exception
    {
        // An RFC 1034 root-label trailing dot must not let a host escape an excluded rfc822Name or
        // URI subtree, matching the dNSName canonicalisation.
        PKIXNameConstraintValidator emailV = new PKIXNameConstraintValidator();
        emailV.addExcludedSubtree(new GeneralSubtree(new GeneralName(GeneralName.rfc822Name, "bank.com")));
        try
        {
            emailV.checkExcluded(new GeneralName(GeneralName.rfc822Name, "ceo@bank.com."));
            fail("trailing-dot email must be caught by the excluded bank.com subtree");
        }
        catch (PKIXNameConstraintValidatorException e)
        {
            // expected
        }

        PKIXNameConstraintValidator uriV = new PKIXNameConstraintValidator();
        uriV.addExcludedSubtree(new GeneralSubtree(new GeneralName(GeneralName.uniformResourceIdentifier, "competitor.example")));
        try
        {
            uriV.checkExcluded(new GeneralName(GeneralName.uniformResourceIdentifier, "https://competitor.example./"));
            fail("trailing-dot URI host must be caught by the excluded competitor.example subtree");
        }
        catch (PKIXNameConstraintValidatorException e)
        {
            // expected
        }

        PKIXNameConstraintValidator dnsV = new PKIXNameConstraintValidator();
        dnsV.addExcludedSubtree(new GeneralSubtree(new GeneralName(GeneralName.dNSName, "example.com")));
        try
        {
            dnsV.checkExcluded(new GeneralName(GeneralName.dNSName, "foo.example.com."));
            fail("trailing-dot dNSName must be caught by the excluded example.com subtree");
        }
        catch (PKIXNameConstraintValidatorException e)
        {
            // expected
        }

        // A directoryName permitted constraint must match as an INITIAL PREFIX of the subject
        // (RFC 5280 4.2.1.10), not as a subsequence at an arbitrary offset. Prepending an RDN ahead
        // of the permitted sequence must not satisfy the constraint.
        GeneralName permittedDN = new GeneralName(GeneralName.directoryName,
            new X500Name(RFC4519Style.INSTANCE, "ou=permittedSubtree1, o=Test Certificates 2011, c=US"));
        GeneralName prefixSubject = new GeneralName(GeneralName.directoryName,
            new X500Name(RFC4519Style.INSTANCE, "cn=Valid DN nameConstraints EE Certificate Test1, ou=permittedSubtree1, o=Test Certificates 2011, c=US"));
        GeneralName prependedSubject = new GeneralName(GeneralName.directoryName,
            new X500Name(RFC4519Style.INSTANCE, "cn=Valid DN nameConstraints EE Certificate Test1, ou=permittedSubtree1, o=Test Certificates 2011, c=US, o=Injected"));

        isTrue("prefix subject must be permitted", isPermitted(permittedDN, prefixSubject));
        isTrue("subject with an RDN prepended before the permitted sequence must NOT be permitted",
            !isPermitted(permittedDN, prependedSubject));

        // The relaxed anywhere-match needed for GSMA SGP.22 is still available, but only as an
        // explicit opt-in via Properties.X509_SGP22_NAME_CONSTRAINTS.
        Properties.setThreadOverride(Properties.X509_SGP22_NAME_CONSTRAINTS, true);
        try
        {
            isTrue("SGP.22 override must restore the relaxed anywhere-match",
                isPermitted(permittedDN, prependedSubject));
        }
        finally
        {
            Properties.removeThreadOverride(Properties.X509_SGP22_NAME_CONSTRAINTS);
        }

        isTrue("the SGP.22 override must not outlive the thread override",
            !isPermitted(permittedDN, prependedSubject));

        testNameConstraintBypassVariants();
        testEmptyLabelRefused();
    }

    private void testNameConstraintBypassVariants()
        throws Exception
    {
        // rfc822Name: every constraint form (mailbox, host, sub-domain) canonicalises the trailing dot
        GeneralName mailbox = new GeneralName(GeneralName.rfc822Name, "ceo@bank.com");
        isTrue("trailing-dot email must hit an excluded mailbox",
            isExcluded(mailbox, new GeneralName(GeneralName.rfc822Name, "ceo@bank.com.")));
        isTrue("other mailbox must not be excluded",
            !isExcluded(mailbox, new GeneralName(GeneralName.rfc822Name, "cfo@bank.com.")));

        GeneralName emailSubDomain = new GeneralName(GeneralName.rfc822Name, ".bank.com");
        isTrue("trailing-dot email must hit an excluded sub-domain",
            isExcluded(emailSubDomain, new GeneralName(GeneralName.rfc822Name, "ceo@mail.bank.com.")));
        isTrue("trailing-dot email must hit an excluded host in upper case",
            isExcluded(new GeneralName(GeneralName.rfc822Name, "bank.com"),
                new GeneralName(GeneralName.rfc822Name, "ceo@BANK.COM.")));
        isTrue("unrelated trailing-dot email must not be excluded",
            !isExcluded(new GeneralName(GeneralName.rfc822Name, "bank.com"),
                new GeneralName(GeneralName.rfc822Name, "ceo@example.com.")));
        isTrue("trailing dot on a sub-domain constraint must still match",
            isExcluded(new GeneralName(GeneralName.rfc822Name, ".bank.com."),
                new GeneralName(GeneralName.rfc822Name, "ceo@mail.bank.com")));

        GeneralName emailHost = new GeneralName(GeneralName.rfc822Name, "bank.com");
        isTrue("trailing-dot email must stay inside a permitted host",
            isPermitted(emailHost, new GeneralName(GeneralName.rfc822Name, "ceo@bank.com.")));
        isTrue("trailing-dot email outside a permitted host must be rejected",
            !isPermitted(emailHost, new GeneralName(GeneralName.rfc822Name, "ceo@evil.com.")));

        // uniformResourceIdentifier: host and sub-domain constraints, with and without a port
        GeneralName uriHost = new GeneralName(GeneralName.uniformResourceIdentifier, "competitor.example");
        isTrue("trailing-dot URI host with port must be excluded",
            isExcluded(uriHost, new GeneralName(GeneralName.uniformResourceIdentifier, "https://competitor.example.:443/path")));
        isTrue("unrelated trailing-dot URI host must not be excluded",
            !isExcluded(uriHost, new GeneralName(GeneralName.uniformResourceIdentifier, "https://friend.example./")));

        GeneralName uriSubDomain = new GeneralName(GeneralName.uniformResourceIdentifier, ".competitor.example");
        isTrue("trailing-dot URI host must hit an excluded sub-domain",
            isExcluded(uriSubDomain, new GeneralName(GeneralName.uniformResourceIdentifier, "https://www.competitor.example./")));
        isTrue("trailing-dot URI host outside a permitted host must be rejected",
            !isPermitted(uriHost, new GeneralName(GeneralName.uniformResourceIdentifier, "https://evil.example./")));

        // dNSName: permitted side and a trailing dot on the constraint itself
        GeneralName dnsDomain = new GeneralName(GeneralName.dNSName, "example.com");
        isTrue("trailing-dot dNSName must stay inside a permitted domain",
            isPermitted(dnsDomain, new GeneralName(GeneralName.dNSName, "foo.example.com.")));
        isTrue("trailing-dot dNSName outside a permitted domain must be rejected",
            !isPermitted(dnsDomain, new GeneralName(GeneralName.dNSName, "foo.evil.com.")));
        isTrue("trailing dot on a dNSName constraint must still match",
            isExcluded(new GeneralName(GeneralName.dNSName, "example.com."),
                new GeneralName(GeneralName.dNSName, "foo.example.com")));

        // directoryName: the example from the advisory, C=FR,O=Attacker,C=US,O=TrustedOrg,CN=x
        GeneralName trustedOrg = new GeneralName(GeneralName.directoryName, new X500Name("C=US,O=TrustedOrg"));
        isTrue("legitimate subject must be permitted",
            isPermitted(trustedOrg, new GeneralName(GeneralName.directoryName, new X500Name("C=US,O=TrustedOrg,CN=x"))));
        isTrue("subject with prepended RDNs must NOT be permitted",
            !isPermitted(trustedOrg, new GeneralName(GeneralName.directoryName, new X500Name("C=FR,O=Attacker,C=US,O=TrustedOrg,CN=x"))));
    }

    /**
     * Only the single root-label dot of RFC 1034 sec. 3.1 is canonicalized away. A host carrying any
     * other empty label - a second trailing dot, a doubled dot, a leading dot - is not a name
     * RFC 5280 sec. 4.2.1.6 admits, and stripping the extra dots would decide on the caller's behalf
     * that "example.com.." names example.com. It is refused instead, in both directions, so it can
     * neither escape an excluded subtree nor be admitted by a permitted one.
     */
    private void testEmptyLabelRefused()
        throws Exception
    {
        // dNSName: every shape of empty label is refused, whichever domain the name appears to carry.
        isTrue("two trailing dots must be refused",
            isExcluded(dnsName("example.com"), dnsName("example.com..")));
        isTrue("three trailing dots must be refused",
            isExcluded(dnsName("example.com"), dnsName("example.com...")));
        isTrue("a doubled inner dot must be refused",
            isExcluded(dnsName("example.com"), dnsName("foo..example.com")));
        isTrue("a leading dot must be refused",
            isExcluded(dnsName("example.com"), dnsName(".example.com")));
        isTrue("a sibling domain with an empty label must be refused too",
            isExcluded(dnsName("example.com"), dnsName("notexample.com..")));

        // the permitted direction refuses it as well, so canonicalizing has not admitted anything new.
        isTrue("an empty label must not be permitted",
            !isPermitted(dnsName("example.com"), dnsName("example.com..")));
        isTrue("a well-formed name is still permitted",
            isPermitted(dnsName("example.com"), dnsName("example.com.")));

        // rfc822Name and URI share the guard, applied to the host.
        isTrue("two trailing dots on a mail host must be refused",
            isExcluded(emailName("bank.com"), emailName("ceo@bank.com..")));
        isTrue("two trailing dots on a URI host must be refused",
            isExcluded(uriName("competitor.example"), uriName("https://competitor.example../")));

        // the guard is scoped to the host: a quoted local part may legally carry a doubled dot.
        isTrue("a doubled dot in a quoted local part must not be refused, and the host still matches",
            isExcluded(emailName("bank.com"), emailName("\"a..b\"@bank.com")));

        // a bare "." is the root label, not an empty one, and is left alone.
        isTrue("a bare root label must not be refused", !isExcluded(dnsName("example.com"), dnsName(".")));

        // nothing is refused where no constraint of that type is in force.
        isTrue("an empty label is immaterial with no dNSName constraint",
            !isExcluded(emailName("bank.com"), dnsName("example.com..")));
    }

    private static GeneralName dnsName(String name)
    {
        return new GeneralName(GeneralName.dNSName, name);
    }

    private static GeneralName emailName(String name)
    {
        return new GeneralName(GeneralName.rfc822Name, name);
    }

    private static GeneralName uriName(String name)
    {
        return new GeneralName(GeneralName.uniformResourceIdentifier, name);
    }

    private boolean isExcluded(GeneralName constraint, GeneralName name)
        throws Exception
    {
        PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
        constraintValidator.addExcludedSubtree(new GeneralSubtree(constraint));

        try
        {
            constraintValidator.checkExcluded(name);
            return false;
        }
        catch (PKIXNameConstraintValidatorException e)
        {
            return true;
        }
    }

    private boolean isPermitted(GeneralName constraint, GeneralName name)
        throws Exception
    {
        PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
        constraintValidator.intersectPermittedSubtree(new GeneralSubtree(constraint));

        try
        {
            constraintValidator.checkPermitted(name);
            return true;
        }
        catch (PKIXNameConstraintValidatorException e)
        {
            return false;
        }
    }

    /**
     * Tests string based GeneralNames for inclusion or exclusion.
     * 
     * @param nameType The {@link GeneralName} type to test.
     * @param testName The name to test.
     * @param testNameIsConstraint The names where <code>testName</code> must
     *            be included and excluded.
     * @param testNameIsNotConstraint The names where <code>testName</code>
     *            must not be excluded and included.
     * @param testNames1 Operand 1 of test names to use for union and
     *            intersection testing.
     * @param testNames2 Operand 2 of test names to use for union and
     *            intersection testing.
     * @param testUnion The union results.
     * @param testInterSection The intersection results.
     * @throws Exception If an unexpected exception occurs.
     */
    private void testConstraints(
        int nameType,
        String testName,
        String[] testNameIsConstraint,
        String[] testNameIsNotConstraint,
        String[] testNames1,
        String[] testNames2,
        String[][] testUnion,
        String[] testInterSection) throws Exception
    {
        for (int i = 0; i < testNameIsConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, testNameIsConstraint[i])));
            constraintValidator.checkPermitted(new GeneralName(nameType, testName));
        }
        for (int i = 0; i < testNameIsNotConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, testNameIsNotConstraint[i])));
            try
            {
                constraintValidator.checkPermitted(new GeneralName(nameType, testName));
                fail("not permitted name allowed: " + nameType);
            }
            catch (PKIXNameConstraintValidatorException e)
            {
                // expected
            }
        }
        for (int i = 0; i < testNameIsConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, testNameIsConstraint[i])));
            try
            {
                constraintValidator.checkExcluded(new GeneralName(nameType, testName));
                fail("excluded name missed: " + nameType);
            }
            catch (PKIXNameConstraintValidatorException e)
            {
                // expected
            }
        }
        for (int i = 0; i < testNameIsNotConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, testNameIsNotConstraint[i])));
            constraintValidator.checkExcluded(new GeneralName(nameType, testName));
        }
        for (int i = 0; i < testNames1.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, testNames1[i])));
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, testNames2[i])));
            PKIXNameConstraintValidator constraints2 = new PKIXNameConstraintValidator();
            for (int j = 0; j < testUnion[i].length; j++)
            {
                constraints2.addExcludedSubtree(new GeneralSubtree(
                    new GeneralName(nameType, testUnion[i][j])));
            }
            if (!constraints2.equals(constraintValidator))
            {
                fail("union wrong: " + nameType);
            }
            constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, testNames1[i])));
            constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, testNames2[i])));
            constraints2 = new PKIXNameConstraintValidator();
            if (testInterSection[i] != null)
            {
                constraints2.intersectPermittedSubtree(new GeneralSubtree(
                    new GeneralName(nameType, testInterSection[i])));
            }
            else
            {
                constraints2.intersectEmptyPermittedSubtree(nameType);
            }
            if (!constraints2.equals(constraintValidator))
            {
                fail("intersection wrong: " + nameType);
            }
        }
    }

    /**
     * Tests byte array based GeneralNames for inclusion or exclusion.
     * 
     * @param nameType The {@link GeneralName} type to test.
     * @param testName The name to test.
     * @param testNameIsConstraint The names where <code>testName</code> must
     *            be included and excluded.
     * @param testNameIsNotConstraint The names where <code>testName</code>
     *            must not be excluded and included.
     * @param testNames1 Operand 1 of test names to use for union and
     *            intersection testing.
     * @param testNames2 Operand 2 of test names to use for union and
     *            intersection testing.
     * @param testUnion The union results.
     * @param testInterSection The intersection results.
     * @throws Exception If an unexpected exception occurs.
     */
    private void testConstraints(
        int nameType,
        byte[] testName,
        byte[][] testNameIsConstraint,
        byte[][] testNameIsNotConstraint,
        byte[][] testNames1,
        byte[][] testNames2,
        byte[][][] testUnion,
        byte[][] testInterSection) throws Exception
    {
        for (int i = 0; i < testNameIsConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, new DEROctetString(
                    testNameIsConstraint[i]))));
            constraintValidator.checkPermitted(new GeneralName(nameType,
                new DEROctetString(testName)));
        }
        for (int i = 0; i < testNameIsNotConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, new DEROctetString(
                    testNameIsNotConstraint[i]))));
            try
            {
                constraintValidator.checkPermitted(new GeneralName(nameType,
                    new DEROctetString(testName)));
                fail("not permitted name allowed: " + nameType);
            }
            catch (PKIXNameConstraintValidatorException e)
            {
                // expected
            }
        }
        for (int i = 0; i < testNameIsConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, new DEROctetString(testNameIsConstraint[i]))));
            try
            {
                constraintValidator.checkExcluded(new GeneralName(nameType,
                    new DEROctetString(testName)));
                fail("excluded name missed: " + nameType);
            }
            catch (PKIXNameConstraintValidatorException e)
            {
                // expected
            }
        }
        for (int i = 0; i < testNameIsNotConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, new DEROctetString(testNameIsNotConstraint[i]))));
            constraintValidator.checkExcluded(new GeneralName(nameType,
                new DEROctetString(testName)));
        }
        for (int i = 0; i < testNames1.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, new DEROctetString(testNames1[i]))));
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, new DEROctetString(testNames2[i]))));
            PKIXNameConstraintValidator constraints2 = new PKIXNameConstraintValidator();
            for (int j = 0; j < testUnion[i].length; j++)
            {
                constraints2.addExcludedSubtree(new GeneralSubtree(
                    new GeneralName(nameType, new DEROctetString(
                        testUnion[i][j]))));
            }
            if (!constraints2.equals(constraintValidator))
            {
                fail("union wrong: " + nameType);
            }
            constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, new DEROctetString(testNames1[i]))));
            constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, new DEROctetString(testNames2[i]))));
            constraints2 = new PKIXNameConstraintValidator();
            if (testInterSection[i] != null)
            {
                constraints2.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, new DEROctetString(
                    testInterSection[i]))));
            }
            else
            {
                constraints2.intersectEmptyPermittedSubtree(nameType);
            }

            if (!constraints2.equals(constraintValidator))
            {
                fail("intersection wrong: " + nameType);
            }
        }
    }

    public static void main(String[] args)
    {
        runTest(new PKIXNameConstraintsTest());
    }
}
