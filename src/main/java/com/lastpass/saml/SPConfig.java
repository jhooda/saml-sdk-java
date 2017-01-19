/*
 * SPConfig - configuration settings for a service provider.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 * Copyright (c) 2014 LastPass, Inc.
 */
package com.lastpass.saml;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

import org.opensaml.Configuration;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.common.xml.SAMLConstants;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.bind.DatatypeConverter;

/**
 * SPConfig contains basic information about the service
 * that is asking for authorization.  This information is
 * put into the auth request sent to the IdP.
 */
public class SPConfig
{
    /** From whom requests are sent */
    private String entityId;

    /** Where the assertions are sent */
    private String acs;

    /** Certificate used to sign assertions */
    private Certificate cert;

    /** Private key used for decrypting assertions */
    private PrivateKey privateKey;

    /**
     * Construct a new, empty SPConfig.
     */
    public SPConfig()
    {

    }
    /**
     * Construct a new SPConfig from a metadata XML file.
     *
     * @param metadataFile File where the metadata lives
     *
     * @throws SAMLException if an error condition occurs while trying to parse and process
     *              the metadata
     */
    public SPConfig(File metadataFile)
        throws SAMLException
    {
        FileInputStream inputStream;
        try {
            inputStream = new FileInputStream(metadataFile);
        }
        catch (java.io.IOException e) {
            throw new SAMLException(e);
        }

        try {
            init(inputStream);
        } finally {
            try {
                inputStream.close();
            }
            catch (java.io.IOException e) {
                //Ignore
            }
        }
    }

    /**
     * Construct a new SPConfig from a metadata XML input stream.
     *
     * @param inputStream  An input stream containing a metadata XML document
     *
     * @throws SAMLException if an error condition occurs while trying to parse and process
     *              the metadata
     */
    public SPConfig(InputStream inputStream)
        throws SAMLException
    {
        init(inputStream);
    }

    private void init(InputStream inputStream)
            throws SAMLException
    {
        BasicParserPool parsers = new BasicParserPool();
        parsers.setNamespaceAware(true);

        EntityDescriptor edesc;

        try {
            Document doc = parsers.parse(inputStream);
            Element root = doc.getDocumentElement();

            UnmarshallerFactory unmarshallerFactory =
                Configuration.getUnmarshallerFactory();

            edesc = (EntityDescriptor) unmarshallerFactory
                .getUnmarshaller(root)
                .unmarshall(root);
        }
        catch (org.opensaml.xml.parse.XMLParserException e) {
            throw new SAMLException(e);
        }
        catch (org.opensaml.xml.io.UnmarshallingException e) {
            throw new SAMLException(e);
        }

        // fetch sp information
        SPSSODescriptor spDesc = edesc.getSPSSODescriptor(
            "urn:oasis:names:tc:SAML:2.0:protocol");

        if (spDesc == null)
            throw new SAMLException("No SP SSO descriptor found");

        // get first redirect or post binding
        String acsUrl = null;
        for (AssertionConsumerService svc: spDesc.getAssertionConsumerServices()) {
            if (svc.getBinding().equals(SAMLConstants.SAML2_REDIRECT_BINDING_URI) ||
                svc.getBinding().equals(SAMLConstants.SAML2_POST_BINDING_URI)) {
                acsUrl = svc.getLocation();
                break;
            }
        }

        if (acsUrl == null)
            throw new SAMLException("No acceptable Assertion Consumer Service found");

        this.setEntityId(edesc.getEntityID());
        this.setAcs(acsUrl);
        // extract the first signing cert from the file
        Certificate cert = null;

        find_cert_loop:
        for (KeyDescriptor kdesc: spDesc.getKeyDescriptors()) {
            if (kdesc.getUse() != UsageType.SIGNING)
                continue;

            KeyInfo ki = kdesc.getKeyInfo();
            if (ki == null)
                continue;

            for (X509Data x509data: ki.getX509Datas()) {
                for (X509Certificate xcert: x509data.getX509Certificates()) {
                    try {
                        cert = certFromString(xcert.getValue());
                        break find_cert_loop;
                    } catch (CertificateException e) {
                        // keep trying certs; if we don't have one we'll
                        // throw a SAMLException at the end.
                    }
                }
            }
        }
        if (cert == null)
            throw new SAMLException("No valid signing cert found");

        this.setCert(cert);

    }

    private Certificate certFromString(String b64data)
        throws CertificateException
    {
        byte[] decoded = DatatypeConverter.parseBase64Binary(b64data);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return cf.generateCertificate(new ByteArrayInputStream(decoded));
    }

    /**
     * Set the SP Entity Id.
     */
    public void setEntityId(String entityId)
    {
        this.entityId = entityId;
    }

    /**
     * Get the SP Entity Id.
     */
    public String getEntityId()
    {
        return this.entityId;
    }

    /**
     * Set the SP ACS URL.  Auth responses are posted
     * here.
     */
    public void setAcs(String acs)
    {
        this.acs = acs;
    }

    /**
     * Get the IdP login URL.
     */
    public String getAcs()
    {
        return this.acs;
    }

    /**
     * Set the SP public key certificate.
     * The certificate is used to sign
     * assertion.
     */
    public void setCert(Certificate cert)
    {
        this.cert = cert;
    }

    /**
     * Get the Idp public key certificate.
     */
    public Certificate getCert() {
        return this.cert;
    }

    /**
     * Set private key used for decrypting assertions.
     */
    public void setPrivateKey(PrivateKey privateKey)
    {
        this.privateKey = privateKey;
    }

    /**
     * Get private key used for decrypting assertions.
     */
    public PrivateKey getPrivateKey()
    {
        return this.privateKey;
    }
}
