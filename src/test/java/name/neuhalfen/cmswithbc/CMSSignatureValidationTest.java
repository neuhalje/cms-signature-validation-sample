package name.neuhalfen.cmswithbc;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Objects;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CMSSignatureValidationTest {

    @BeforeAll
    static public void before() {
        if (Security.getProvider(PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    X509Certificate cert(String folder) throws IOException, CertificateException, NoSuchProviderException {
        try (InputStream certificate = getClass().getResourceAsStream("/" +folder + "/signer.crt")) {
            return Util.loadCertificate(certificate);
        }
    }

    QRCodeParser.QRCode code(String folder) throws IOException {
        try (InputStream resourceAsStream = getClass().getResourceAsStream("/" + folder + "/qrcode.spec")) {
            byte[] data = new byte[8192];
            int len = Objects.requireNonNull(resourceAsStream).read(data);
            return QRCodeParser.parse(new String(data, 0, len));

        }
    }

    QRCodeParser.QRCode trustedQRCode() throws IOException {
        return code("trusted");
    }

    X509Certificate trustedCert() throws IOException, CertificateException, NoSuchProviderException {
        return cert("trusted");
    }

    X509Certificate untrustedCert() throws IOException, CertificateException, NoSuchProviderException {
        return cert("untrusted");
    }

    @Test
    public void notTamperedGoodCert_validates() throws IOException, CertificateException, NoSuchProviderException {
        CMSSignatureValidation sut = new CMSSignatureValidation();
        QRCodeParser.QRCode qrCode = trustedQRCode();
        X509Certificate trustedCert = trustedCert();
        assertTrue(sut.validateSignature(trustedCert, qrCode.data, qrCode.signature));
    }

    @Test
    public void tamperedGoodCert_validatesNot() throws IOException, CertificateException, NoSuchProviderException {
        CMSSignatureValidation sut = new CMSSignatureValidation();
        QRCodeParser.QRCode qrCode = trustedQRCode();
        String tampered = qrCode.data.replaceFirst("PLAP", "TAMP");

        X509Certificate trustedCert = trustedCert();


        assertFalse(sut.validateSignature(trustedCert, tampered, qrCode.signature));
    }
    /**
     * Signing and validation certs are different. This will fail.
     */
    @Test
    public void notTamperedWrongCert_validatesNot() throws IOException, CertificateException, NoSuchProviderException {
        CMSSignatureValidation sut = new CMSSignatureValidation();
        QRCodeParser.QRCode qrCode = trustedQRCode();
        X509Certificate untrustedCert = untrustedCert();

        assertFalse(sut.validateSignature(untrustedCert, qrCode.data, qrCode.signature));
    }

}