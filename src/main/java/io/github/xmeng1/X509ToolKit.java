package io.github.xmeng1;


import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

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
}
