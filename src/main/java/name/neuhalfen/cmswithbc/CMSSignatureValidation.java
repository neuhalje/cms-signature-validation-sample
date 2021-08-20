package name.neuhalfen.cmswithbc;


import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;

import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

public final class CMSSignatureValidation {


    /**
     * @param signerCert The certificate used to sign the code
     * @param signed     The qr code without signature and without last delimiter ("PLAP01Demo2021-03-08T19:54:51Z|23413804-e180-45b3-a077-3ce73045d7c3|U|demo_ast_id|021234")
     * @param signature  The signature ("MIICSgYJKo...58Qc=")
     * @return true: the data has been signed by the passed cert
     */
    public boolean validateSignature(X509Certificate signerCert, String signed, String signature) {
        byte[] signatureBytes = Base64
                .getDecoder().decode(signature);
        byte[] signedData = signed.getBytes();
        return validateSignature(signerCert, signedData, signatureBytes);
    }

    private boolean validateSignature(X509Certificate signerCert, byte[] data, byte[] signatureBytes) {
        boolean verified = false;
        try {
            SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider(PROVIDER_NAME).build(signerCert);

            CMSSignedData cms = new CMSSignedData(new CMSProcessableByteArray(data), signatureBytes);
            SignerInformationStore signers = cms.getSignerInfos();
            Collection<SignerInformation> c = signers.getSigners();
            for (SignerInformation signer : c) {
                verified |= signer.verify(verifier);
            }
            return verified;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

    }

}