package name.neuhalfen.cmswithbc;


import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

public final class CMSSignatureValidation {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        byte[] signatureBytes = Base64
                .getDecoder().decode("MIICSgYJKoZIhvcNAQcCoIICOzCCAjcCAQExDTALBglghkgBZQMEAgEwCwYJKoZIhvcNAQcBMYICFDCCAhACAQEwazBTMQswCQYDVQQGEwJERTEMMAoGA1UECAwDTlJXMQ0wCwYDVQQHDARCb25uMQ4wDAYDVQQLDAVQTEFQUDEXMBUGA1UEAwwOcXItY29kZS1zaWduZXICFBa2NOjnUmGcwc7r8WjR3ilZExYGMAsGCWCGSAFlAwQCATANBgkqhkiG9w0BAQEFAASCAYCsTq6aQKgETVzfPjcyLfh19h7PRFKh4aG88Fao8dpWGhsRhIkRQ181f8BB8JSEJ2oKgZVQi3+AxGnGapHBXkhiS90iLyrwGnXXJv88iDWEpfK0n2OrBXWYItwFB10dI5qtsa95O7BKEw8eNLuqYluHmYTihxi1XmaOlrAGJ9pIgI++rZgIyTlmyDx227urzDkzmX22o21gPJZ54Ud4yqVpmku7hoBGYpTRTJ9JyJ1iW2Y/0Ly9mXKSW9Skev/vgptlnCJXQF6gnCxFW2RqSyxCkXI/mlEiyVjl8HAFeYNBOLS3IZJSoNJ/F3nH5oXwNc1gPeL73OAI0cmNPRGc6OagFUQu24taL8+ulgwyLHRp2VyqyvbEhyrtaA0w8stMN7jh5POYqkYK/zKBdZYcSyOnfM1lK9hBTm69JB/0sIojbRM4r/6s4sS6Nwxfe/lPKlnZGbNwp5O/i2n+1HZgRsgH4UOIpYeFWbTYMdvnmGlcgSmKn/+7QrlJcSdxp3n58Qc=");
        byte[] data = "PLAP01Demo2021-03-08T19:54:51Z|23413804-e180-45b3-a077-3ce73045d7c3|U|demo_ast_id|021234".getBytes();

        try (InputStream certificate = new FileInputStream("/home/jens/Projects/java/cms-with-boucncy-castle/src/test/resources/good/signer.crt")) {
            X509Certificate signerCert = loadCertificate(certificate);
            boolean validated = validateSignature(signerCert, data, signatureBytes);
            System.out.println(validated ? "Signature OK" : "Signature NOT OK!");
        }
    }

    private static X509Certificate loadCertificate(InputStream is) throws CertificateException, NoSuchProviderException {
        CertificateFactory fact = CertificateFactory.getInstance("X.509", PROVIDER_NAME);
        X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
        return cer;
    }


    private static boolean validateSignature(X509Certificate signerCert, byte[] data, byte[] signatureBytes) {
        boolean verified = false;
        try {
            CMSSignedData cms = new CMSSignedData(new CMSProcessableByteArray(data), signatureBytes);
            SignerInformationStore signers = cms.getSignerInfos();
            Collection c = signers.getSigners();
            for (Object aC : c) {
                SignerInformation signer = (SignerInformation) aC;

                SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider(PROVIDER_NAME).build(signerCert);
                verified = signer.verify(verifier);
            }
            return verified;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

    }

}