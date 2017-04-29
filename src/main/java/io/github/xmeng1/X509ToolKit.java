package io.github.xmeng1;


import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;

/**
 * User:    Xin Meng
 * Date:    29/04/17
 * Project: x509toolkit
 */
public class X509ToolKit {

    private static void closeSilent(final InputStream is) throws X509ToolKitException {
        if (is == null) return;
        try {
            is.close();
        } catch (Exception e) {
            throw new X509ToolKitException(e.getMessage());
        }
    }

    /**
     * Get X509 Certificate from the fileName in resource folder
     *
     * The Type of CertificateFactory is from the link <a href="
     * http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html">
     * Java Cryptography Architecture Standard Algorithm Name Documentation</a>
     *
     * @param fileNameInResource fileName with Path of the certificate under the resource folder
     * @return X509Certificate
     * @throws X509ToolKitException E_CERT_LOAD_X509_CERT_FAIL
     */
    public static X509Certificate loadX509Cert(String fileNameInResource)
            throws X509ToolKitException {
        InputStream bis = null;
        X509Certificate crt;
        try {
            File file = new File(X509ToolKit.class.getResource(fileNameInResource).getPath());
            bis = new FileInputStream(file);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            crt = (X509Certificate) cf.generateCertificate(bis);
        } catch (IOException | CertificateException e) {
            throw new X509ToolKitException(e.getMessage());
        } finally {
            closeSilent(bis);
        }
        return crt;
    }

    /**
     * Get Private Key from the fileName in resource folder
     *
     * The Type of KeyFactory is from the link <a href="
     * http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html">
     * Java Cryptography Architecture Standard Algorithm Name Documentation</a>
     *
     * @param fileNameInResource  fileName with Path of the key under the resource folder
     * @return PrivateKey
     * @throws X509ToolKitException E_CERT_LOAD_PRIVATE_KEY_FAIL
     */
    public static PrivateKey loadPrivateKey(String fileNameInResource) throws X509ToolKitException {
        try {
            File file = new File(X509ToolKit.class.getResource(fileNameInResource).getPath());
            byte[] buf = IOUtils.toByteArray(new FileInputStream(file));
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(buf);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(pkcs8EncodedKeySpec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new X509ToolKitException(e.getMessage());
        }
    }

    /**
     * Generates CA signed version 3  {@link X509Certificate}.
     *
     * @param keyPair              the key pair
     * @param caPrivateKey         the CA private key
     * @param caCert               the CA certificate
     * @param x500Name             the xName name
     * @param validityYear         the validity years for the certificate
     * @param basicConstraintsFlag identify the certificate as a CA certificate
     *                             (Optional) Select the Set the CA flag in the Basic Constraints extension option to "true" option to identify the certificate as a CA certificate.
     *                             <p>
     *                             This option changes the Basic Constraints extension CA flag to true and sets the KeyCertSign bit. Some service providers (apps) require that this extension value be included with SAML certificates. Most apps do not. If you use an app that requires this extension value, select this option and use this certificate for those apps. We recommend that you use a separate certificate, without this option enabled, for apps that do not require that Basic Constraint extension.
     * @return the x509 certificate
     * @throws X509ToolKitException Result.Status.E_LOGON_CHALLENGE_GENERATE_ERROR
     */
    public static X509Certificate generateV3Certificate(
            KeyPair keyPair,
            PrivateKey caPrivateKey,
            X509Certificate caCert,
            String x500Name,
            Integer validityYear,
            Boolean basicConstraintsFlag,
            SignatureAlgorithm signatureAlgorithm) throws X509ToolKitException {
        try {
            // subject
            X500Name subjectDN = new X500Name(x500Name);

            // Serial Number by using SHA1(Pseudorandom number generator)
            // compare with NATIVEPRNG http://stackoverflow.com/questions/27622625/securerandom-with-nativeprng-vs-sha1prng
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            BigInteger serialNumber = BigInteger.valueOf(Math.abs(random.nextInt()));

            // Validity
            Date notBefore = new Date(System.currentTimeMillis());
            Date notAfter = new Date(System.currentTimeMillis() + (((1000L * 60 * 60 * 24 * 30)) * 12) * validityYear);

            // SubjectPublicKeyInfo, use getInstance replace new
            SubjectPublicKeyInfo subjPubKeyInfo =
                    SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(keyPair.getPublic().getEncoded()));

            X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(new X500Name(caCert.getSubjectDN().getName()),
                    serialNumber, notBefore, notAfter, subjectDN, subjPubKeyInfo);

            // Extension
            // create DigestCalculator for calculate the Digest information of SubjectKeyIdentifier
            DigestCalculator digCalc = new BcDigestCalculatorProvider()
                    .get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
            X509ExtensionUtils x509ExtensionUtils = new X509ExtensionUtils(digCalc);

            // Subject Key Identifier
            certGen.addExtension(Extension.subjectKeyIdentifier, false,
                    x509ExtensionUtils.createSubjectKeyIdentifier(subjPubKeyInfo));

            // Authority Key Identifier
            certGen.addExtension(Extension.authorityKeyIdentifier, false,
                    x509ExtensionUtils.createAuthorityKeyIdentifier(subjPubKeyInfo));

            // Key Usage only for digital signature
            certGen.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature));

            // Extended Key Usage, do not use extended key usage
            //KeyPurposeId[] EKU = new KeyPurposeId[2];
            //EKU[0] = KeyPurposeId.id_kp_emailProtection;
            //EKU[1] = KeyPurposeId.id_kp_serverAuth;
            //certGen.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(EKU));

            // Basic Constraints, need not set the path length pathlen.
            // certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
            certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(basicConstraintsFlag));

            // Content Signer
            ContentSigner sigGen = new JcaContentSignerBuilder(signatureAlgorithm.toString())
                    .setProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider())
                    .build(caPrivateKey);

            // Certificate
            return new JcaX509CertificateConverter()
                    .setProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider())
                    .getCertificate(certGen.build(sigGen));
        } catch (Exception e) {
            throw new X509ToolKitException(e.getMessage());
        }
    }
}
