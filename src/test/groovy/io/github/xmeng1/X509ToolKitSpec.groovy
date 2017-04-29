package io.github.xmeng1

import spock.lang.Specification

import java.security.PrivateKey
import java.security.cert.X509Certificate


/**
 * User:    Xin Meng
 * Date:    29/04/17
 * Project: Default (Template) Project
 */
class X509ToolKitSpec extends Specification {
    def "Load the testing CA X.509 certificate from file" (){
        given: "the CA file name in resource"
        String caFileName = "/certificates/ds-cloud-ca-cert.pem"

        when: "load the private key from the file"
        X509Certificate x509Certificate = X509ToolKit.loadX509Cert(caFileName)

        then: "the information of the X509Certificate should be right"
        x509Certificate.getIssuerDN().toString() ==
                "CN=io.github.xmeng1.testing, OU=Test, O=Test, L=London, ST=London, C=UK"
        println(x509Certificate.toString())
    }

    def "Load Private Key form file"() {
        given: "file name"
        String fileName = "/certificates/pkcs8_key"

        when: "load the private key from the file"
        PrivateKey privateKey = X509ToolKit.loadPrivateKey(fileName)

        then: "private key should be right"
        println(privateKey.algorithm.toString())
        println(privateKey.toString())
    }
}