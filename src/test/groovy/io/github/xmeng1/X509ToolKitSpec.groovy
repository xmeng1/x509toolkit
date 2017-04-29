package io.github.xmeng1

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
/**
 * User:    Xin Meng
 * Date:    29/04/17
 * Project: Default (Template) Project
 */
class X509ToolKitSpec extends Specification {

    @Shared
    String caFileName = "/certificates/ds-cloud-ca-cert.pem"
    @Shared
    String privateKeyFileName = "/certificates/pkcs8_key"
    def "Load the testing CA X.509 certificate from file" (){
        given: "the CA file name in resource"


        when: "load the private key from the file"
        X509Certificate x509Certificate = X509ToolKit.loadX509Cert(caFileName)

        then: "the information of the X509Certificate should be right"
        x509Certificate.getIssuerDN().toString() ==
                "CN=io.github.xmeng1.testing, OU=Test, O=Test, L=London, ST=London, C=UK"
        println(x509Certificate.toString())
    }

    def "Load Private Key form file"() {
        given: "file name"

        when: "load the private key from the file"
        PrivateKey privateKey = X509ToolKit.loadPrivateKey(privateKeyFileName)

        then: "private key should be right"
        println(privateKey.algorithm.toString())
        println(privateKey.toString())
    }

    @Unroll("""Generate x509 certificate by parameter 
x500name: #x500name, 
validYears: #validYears, 
isBasicConstrain: #isBasicConstrain
signatureAlgorithm: #signatureAlgorithm 
and result 
resultX500name: #resultX500 
resultBasicConstrain: #resultBasicConstrain
""")
    def "generate signed x509 certificate by internal CA"() {
        given: "generate an key pair"
        SecureRandom sr = new SecureRandom()
        byte[] values = new byte[20]
        sr.nextBytes(values)
        KeyPair keypair

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA")
        keyGen.initialize(2048, sr)
        keypair = keyGen.generateKeyPair()

        and: "load the CA information"
        X509Certificate rootCACert = X509ToolKit.loadX509Cert(caFileName)
        PrivateKey rootCAPrivateKey = X509ToolKit.loadPrivateKey(privateKeyFileName)

        when: "load the private key from the file"
        X509Certificate x509Certificate = X509ToolKit.generateV3Certificate(
                keypair,rootCAPrivateKey,rootCACert,x500name,validYears,isBasicConstrain,signatureAlgorithm)

        then: "private key should be right"
        x509Certificate.getSubjectX500Principal().toString()==resultX500
        x509Certificate.getBasicConstraints() == resultBasicConstrain
        x509Certificate.getSigAlgName() == signAlgName
        x509Certificate.getSigAlgOID() == signAlgOid.toString()
        where: "the scenarios are"
        x500name | validYears | isBasicConstrain |signatureAlgorithm                            || resultX500 || resultBasicConstrain || signAlgName        || signAlgOid
        "CN=xxx" | 1          | false            | SignatureAlgorithm.SHA1WithRSAEncryption     ||  "CN=xxx"  ||  -1                  ||  "SHA1withRSA"     || PKCSObjectIdentifiers.sha1WithRSAEncryption
        "CN=yyy" | 3          | true             | SignatureAlgorithm.SHA256WithRSAEncryption   ||  "CN=yyy"  ||  Integer.MAX_VALUE   ||  "SHA256withRSA"   || PKCSObjectIdentifiers.sha256WithRSAEncryption
        "CN=yyy" | 3          | true             | SignatureAlgorithm.SHA512WithRSAEncryption   ||  "CN=yyy"  ||  Integer.MAX_VALUE   ||  "SHA512withRSA"   || PKCSObjectIdentifiers.sha512WithRSAEncryption
    }
}