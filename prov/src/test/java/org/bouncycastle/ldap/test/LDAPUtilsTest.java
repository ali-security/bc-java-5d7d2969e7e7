package org.bouncycastle.ldap.test;

import junit.framework.TestCase;
import org.bouncycastle.ldap.LDAPUtils;

/**
 * Checks that values extracted from a DN by LDAPUtils are escaped (RFC 2254/4515)
 * before being placed in an LDAP search filter.
 */
public class LDAPUtilsTest
    extends TestCase
{
    public void testPlainValue()
    {
        assertEquals("Test User", LDAPUtils.parseDN("CN=Test User,O=Org,C=AU", "cn"));
        assertEquals("Test User", LDAPUtils.parseDN("CN=Test User", "CN"));
    }

    public void testFilterSpecialCharactersEscaped()
    {
        assertEquals("a\\2ab", LDAPUtils.parseDN("CN=a*b", "cn"));
        assertEquals("a\\28b", LDAPUtils.parseDN("CN=a(b", "cn"));
        assertEquals("a\\29b", LDAPUtils.parseDN("CN=a)b", "cn"));
        assertEquals("a\\5cb", LDAPUtils.parseDN("CN=a\\\\b", "cn"));
        assertEquals("a\\00b", LDAPUtils.parseDN("CN=a\0b", "cn"));
        assertEquals("\\2a", LDAPUtils.parseDN("CN=*", "cn"));
        assertEquals("chars[\\2a\\28\\29\\5c\\00]", LDAPUtils.parseDN("CN=chars[*()\\\\\0]", "cn"));
    }

    public void testFilterInjectionEscaped()
    {
        // a crafted RDN value which, unescaped, would close the substring assertion and
        // inject an additional filter component.
        assertEquals("x\\29\\28uid=admin", LDAPUtils.parseDN("CN=x)(uid=admin", "cn"));
        assertEquals("x\\29\\28uid=admin", LDAPUtils.parseDN("CN=\"x)(uid=admin\"", "cn"));
        assertEquals("\\2a\\29\\28|\\28objectClass=\\2a", LDAPUtils.parseDN("CN=*)(|(objectClass=*", "cn"));
        assertEquals("Org\\29\\28uid=\\2a", LDAPUtils.parseDN("CN=Test User, O=Org)(uid=*", "o"));
    }

    public void testEscapedCommaRetained()
    {
        assertEquals("a,b\\29\\28c", LDAPUtils.parseDN("CN=a\\,b)(c,O=Org", "cn"));
    }

    public void testMissingAttribute()
    {
        assertEquals("", LDAPUtils.parseDN("O=Org,C=AU", "cn"));
    }
}
