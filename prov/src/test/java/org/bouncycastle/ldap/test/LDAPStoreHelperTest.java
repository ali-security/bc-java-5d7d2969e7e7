package org.bouncycastle.ldap.test;

import java.net.InetAddress;
import java.security.Security;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.X509LDAPCertStoreParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509LDAPCertStoreSpi;
import org.bouncycastle.x509.AttributeCertificateHolder;
import org.bouncycastle.x509.X509AttributeCertStoreSelector;
import org.bouncycastle.x509.X509CRLStoreSelector;
import org.bouncycastle.x509.X509CertPairStoreSelector;
import org.bouncycastle.x509.X509CertStoreSelector;
import org.bouncycastle.x509.util.LDAPStoreHelper;

/**
 * Regression tests for LDAP filter injection via LDAPStoreHelper and X509LDAPCertStoreSpi: RDN
 * values taken from subject/issuer names must be escaped before being placed in the LDAP search filter.
 */
public class LDAPStoreHelperTest
    extends TestCase
{
    private static final String BASE_DN = "dc=test";

    private InMemoryDirectoryServer ds;
    private FilterCapture capture;

    public void setUp()
        throws Exception
    {
        capture = new FilterCapture();

        InMemoryDirectoryServerConfig serverConfig = new InMemoryDirectoryServerConfig(BASE_DN);
        serverConfig.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig(
            "listen", InetAddress.getByName("127.0.0.1"), 0, null));
        serverConfig.addInMemoryOperationInterceptor(capture);

        ds = new InMemoryDirectoryServer(serverConfig);
        ds.add("dn: " + BASE_DN, "objectClass: top", "objectClass: domain", "dc: test");
        ds.startListening();
    }

    public void tearDown()
    {
        if (ds != null)
        {
            ds.shutDown(true);
        }
    }

    public void testUserCertificateSubjectInjection()
        throws Exception
    {
        X509CertStoreSelector selector = new X509CertStoreSelector();
        selector.setSubject(principal(BCStyle.CN, "x)(uid=admin").getEncoded());

        createHelper().getUserCertificates(selector);

        checkFilters("cn", "x)(uid=admin", "uid");
        assertTrue(capture.getFilterStrings().contains("(&(|(cn=*x\\29\\28uid=admin*))(|(userCertificate=*)))"));
    }

    public void testUserCertificateSubjectFilterCharacters()
        throws Exception
    {
        X509CertStoreSelector selector = new X509CertStoreSelector();
        selector.setSubject(principal(BCStyle.CN, "chars[*()\0]").getEncoded());

        createHelper().getUserCertificates(selector);

        checkFilters("cn", "chars[*()\0]", null);
        assertTrue(capture.getFilterStrings().contains("(&(|(cn=*chars[\\2a\\28\\29\\00]*))(|(userCertificate=*)))"));
    }

    public void testCACertificateSubjectInjection()
        throws Exception
    {
        X509CertStoreSelector selector = new X509CertStoreSelector();
        selector.setSubject(principal(BCStyle.O, "evil)(objectClass=x").getEncoded());

        createHelper().getCACertificates(selector);

        checkFilters("o", "evil)(objectClass=x", "objectClass");
    }

    public void testCrossCertificatePairSubjectInjection()
        throws Exception
    {
        X509CertStoreSelector forward = new X509CertStoreSelector();
        forward.setSubject(principal(BCStyle.O, "evil)(objectClass=x").getEncoded());
        X509CertPairStoreSelector selector = new X509CertPairStoreSelector();
        selector.setForwardSelector(forward);

        createHelper().getCrossCertificatePairs(selector);

        checkFilters("o", "evil)(objectClass=x", "objectClass");
    }

    public void testAttributeCertificateHolderInjection()
        throws Exception
    {
        X509AttributeCertStoreSelector selector = new X509AttributeCertStoreSelector();
        selector.setHolder(new AttributeCertificateHolder(principal(BCStyle.CN, "x)(uid=admin")));

        createHelper().getAttributeCertificateAttributes(selector);

        checkFilters("cn", "x)(uid=admin", "uid");
    }

    public void testCRLIssuerInjection()
        throws Exception
    {
        X509CRLStoreSelector selector = new X509CRLStoreSelector();
        selector.addIssuer(principal(BCStyle.O, "evil)(objectClass=x"));

        createHelper().getCertificateRevocationLists(selector);

        checkFilters("o", "evil)(objectClass=x", "objectClass");
    }

    public void testCertStoreSpiSubjectInjection()
        throws Exception
    {
        X509CertSelector selector = new X509CertSelector();
        selector.setSubject(principal(BCStyle.CN, "x)(uid=admin").getEncoded());

        createCertStoreSpi().engineGetCertificates(selector);

        checkFilters("cn", "x)(uid=admin", "uid");
        assertTrue(capture.getFilterStrings().contains("(&(cn=*x\\29\\28uid=admin*)(userCertificate=*))"));
    }

    public void testCertStoreSpiCRLIssuerInjection()
        throws Exception
    {
        X509CRLSelector selector = new X509CRLSelector();
        selector.addIssuer(principal(BCStyle.O, "evil)(objectClass=x"));

        createCertStoreSpi().engineGetCRLs(selector);

        checkFilters("o", "evil)(objectClass=x", "objectClass");
    }

    private LDAPStoreHelper createHelper()
    {
        return new LDAPStoreHelper(new X509LDAPCertStoreParameters.Builder(
            "ldap://127.0.0.1:" + ds.getListenPort(), BASE_DN).build());
    }

    /*
        X509LDAPCertStoreSpi uses each attribute name setting as a single name, so search on one
        attribute rather than the space separated defaults.
     */
    private X509LDAPCertStoreSpi createCertStoreSpi()
        throws Exception
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        return new X509LDAPCertStoreSpi(new X509LDAPCertStoreParameters.Builder(
            "ldap://127.0.0.1:" + ds.getListenPort(), BASE_DN)
            .setLdapCACertificateAttributeName("cn")
            .setCACertificateSubjectAttributeName("cn")
            .setLdapCrossCertificateAttributeName("cn")
            .setCrossCertificateSubjectAttributeName("cn")
            .setLdapCertificateRevocationListAttributeName("o")
            .setCertificateRevocationListIssuerAttributeName("o")
            .build());
    }

    private static X500Principal principal(ASN1ObjectIdentifier type, String value)
        throws Exception
    {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);

        builder.addRDN(type, value);

        return new X500Principal(builder.build().getEncoded());
    }

    /**
     * Check that the malicious RDN value reached the directory only as literal assertion data of a
     * substring match on attrName, and that no filter component for injectedAttr was created.
     */
    private void checkFilters(String attrName, String literal, String injectedAttr)
    {
        List filters = capture.getFilters();

        assertFalse("no LDAP search received", filters.isEmpty());

        boolean found = false;
        for (Iterator it = filters.iterator(); it.hasNext();)
        {
            List leaves = new ArrayList();
            collectLeaves((Filter)it.next(), leaves);

            for (Iterator lIt = leaves.iterator(); lIt.hasNext();)
            {
                Filter leaf = (Filter)lIt.next();

                if (injectedAttr != null)
                {
                    assertFalse("injected filter component: " + capture.getFilterStrings(),
                        injectedAttr.equalsIgnoreCase(leaf.getAttributeName()));
                }

                if (leaf.getFilterType() == Filter.FILTER_TYPE_SUBSTRING
                    && attrName.equalsIgnoreCase(leaf.getAttributeName())
                    && leaf.getSubInitialString() == null
                    && leaf.getSubFinalString() == null
                    && leaf.getSubAnyStrings().length == 1
                    && literal.equals(leaf.getSubAnyStrings()[0]))
                {
                    found = true;
                }
            }
        }

        assertTrue("escaped value not found in: " + capture.getFilterStrings(), found);
    }

    private static void collectLeaves(Filter filter, List leaves)
    {
        switch (filter.getFilterType())
        {
        case Filter.FILTER_TYPE_AND:
        case Filter.FILTER_TYPE_OR:
            Filter[] components = filter.getComponents();
            for (int i = 0; i != components.length; i++)
            {
                collectLeaves(components[i], leaves);
            }
            break;
        case Filter.FILTER_TYPE_NOT:
            collectLeaves(filter.getNOTComponent(), leaves);
            break;
        default:
            leaves.add(filter);
        }
    }

    /*
        record the filters actually received by the directory.
     */
    static class FilterCapture
        extends InMemoryOperationInterceptor
    {
        private final List filters = Collections.synchronizedList(new ArrayList());

        public void processSearchResult(InMemoryInterceptedSearchResult result)
        {
            filters.add(result.getRequest().getFilter());

            result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
        }

        List getFilters()
        {
            synchronized (filters)
            {
                return new ArrayList(filters);
            }
        }

        List getFilterStrings()
        {
            List strings = new ArrayList();
            for (Iterator it = getFilters().iterator(); it.hasNext();)
            {
                strings.add(it.next().toString());
            }
            return strings;
        }
    }
}
