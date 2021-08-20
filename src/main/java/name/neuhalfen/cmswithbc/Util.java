package name.neuhalfen.cmswithbc;

import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

public final class Util {
    public static X509Certificate loadCertificate(InputStream is) throws CertificateException, NoSuchProviderException {
        CertificateFactory fact = CertificateFactory.getInstance("X.509", PROVIDER_NAME);
        return (X509Certificate) fact.generateCertificate(is);
    }

    private Util(){}
}
