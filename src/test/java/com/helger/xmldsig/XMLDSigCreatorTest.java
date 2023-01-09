/*
 * Copyright (C) 2014-2023 Philip Helger (www.helger.com)
 * philip[at]helger[dot]com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.helger.xmldsig;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.annotation.Nonnull;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import com.helger.bc.PBCProvider;
import com.helger.commons.CGlobal;
import com.helger.commons.io.file.FileSystemRecursiveIterator;
import com.helger.commons.io.file.IFileFilter;
import com.helger.xml.serialize.read.DOMReader;
import com.helger.xml.serialize.write.XMLWriter;

/**
 * Test class for class {@link XMLDSigCreator}
 *
 * @author Philip Helger
 */
public final class XMLDSigCreatorTest
{
  private static final Logger LOGGER = LoggerFactory.getLogger (XMLDSigCreatorTest.class);

  /**
   * Create a new dummy certificate based on the passed key pair
   *
   * @param kp
   *        KeyPair to use. May not be <code>null</code>.
   * @return A {@link X509Certificate} for further usage
   */
  @Nonnull
  private X509Certificate _createCert (@Nonnull final KeyPair kp) throws Exception
  {
    final PublicKey aPublicKey = kp.getPublic ();
    final PrivateKey aPrivateKey = kp.getPrivate ();
    final ContentSigner aContentSigner = new JcaContentSignerBuilder ("SHA1withRSA").setProvider (PBCProvider.getProvider ())
                                                                                    .build (aPrivateKey);

    // Form yesterday
    final Date aStartDate = new Date (System.currentTimeMillis () - 24 * CGlobal.MILLISECONDS_PER_HOUR);
    // For one year from now
    final Date aEndDate = new Date (System.currentTimeMillis () + 365 * 24 * CGlobal.MILLISECONDS_PER_HOUR);

    final X509v1CertificateBuilder aCertBuilder = new JcaX509v1CertificateBuilder (new X500Principal ("CN=TestIssuer"),
                                                                                   BigInteger.ONE,
                                                                                   aStartDate,
                                                                                   aEndDate,
                                                                                   new X500Principal ("CN=TestSubject"),
                                                                                   aPublicKey);
    final X509CertificateHolder aCertHolder = aCertBuilder.build (aContentSigner);
    // Convert to JCA X509Certificate
    return new JcaX509CertificateConverter ().setProvider (PBCProvider.getProvider ()).getCertificate (aCertHolder);
  }

  @Test
  public void testSign () throws Exception
  {
    // Create a dummy in-memory certificate
    final KeyPairGenerator aKeyPairGenerator = KeyPairGenerator.getInstance ("RSA");
    aKeyPairGenerator.initialize (512);
    final KeyPair aKeyPair = aKeyPairGenerator.generateKeyPair ();
    final X509Certificate aCert = _createCert (aKeyPair);

    for (final File aFile : new FileSystemRecursiveIterator ("src/test/resources/xml-unsigned").withFilter (IFileFilter.fileOnly ()
                                                                                                                       .and (IFileFilter.filenameEndsWith (".xml"))))
    {
      // Read document
      final Document aDoc = DOMReader.readXMLDOM (aFile);
      assertNotNull (aDoc);

      // Apply the signature
      assertFalse (XMLDSigValidator.containsSignature (aDoc));
      new XMLDSigCreator ().applyXMLDSigAsFirstChild (aKeyPair.getPrivate (), aCert, aDoc);
      assertTrue (XMLDSigValidator.containsSignature (aDoc));

      if (false)
        LOGGER.info (XMLWriter.getNodeAsString (aDoc));

      // Validate the signature
      assertTrue (XMLDSigValidator.validateSignature (aDoc).isValid ());

      // Modify the document
      aDoc.getDocumentElement ().appendChild (aDoc.createTextNode ("text"));

      // Validate again - must fail
      assertTrue (XMLDSigValidator.validateSignature (aDoc).isInvalid ());
    }
  }
}
