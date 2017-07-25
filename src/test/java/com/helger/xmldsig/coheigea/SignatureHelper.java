/**
 * Copyright (C) 2014-2017 Philip Helger (www.helger.com)
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
package com.helger.xmldsig.coheigea;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;

import javax.annotation.Nonnull;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.namespace.NamespaceContext;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.Init;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.OutboundXMLSec;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.impl.securityToken.X509SecurityToken;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.SignedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.X509TokenSecurityEvent;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants;
import org.apache.xml.security.transforms.Transforms;
import org.junit.Assert;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.helger.commons.collection.CollectionHelper;
import com.helger.commons.collection.impl.CommonsArrayList;
import com.helger.commons.collection.impl.ICommonsList;
import com.helger.xml.namespace.MapBasedNamespaceContext;

/**
 * Some utility methods for signing/verifying documents
 */
public final class SignatureHelper
{
  static
  {
    Init.init ();
  }

  private SignatureHelper ()
  {}

  @Nonnull
  private static NamespaceContext _createNamespaceContext ()
  {
    final MapBasedNamespaceContext aNC = new MapBasedNamespaceContext ();
    aNC.addMapping ("ds", javax.xml.crypto.dsig.XMLSignature.XMLNS);
    aNC.addMapping ("dsig", javax.xml.crypto.dsig.XMLSignature.XMLNS);
    return aNC;
  }

  /*
   * Sign the document using the DOM API of Apache Santuario - XML Security for
   * Java. It signs a list of QNames that it finds in the Document via XPath.
   */
  public static void signUsingDOM (final Document document,
                                   final List <QName> namesToSign,
                                   final String algorithm,
                                   final Key signingKey,
                                   final X509Certificate signingCert) throws Exception
  {
    final XMLSignature sig = new XMLSignature (document, "", algorithm, CanonicalizationMethod.EXCLUSIVE);
    final Element root = document.getDocumentElement ();
    root.appendChild (sig.getElement ());

    final XPathFactory xpf = XPathFactory.newInstance ();
    final XPath xpath = xpf.newXPath ();
    xpath.setNamespaceContext (_createNamespaceContext ());

    for (final QName nameToSign : namesToSign)
    {
      final String expression = "//*[local-name()='" + nameToSign.getLocalPart () + "']";
      final NodeList elementsToSign = (NodeList) xpath.evaluate (expression, document, XPathConstants.NODESET);
      for (int i = 0; i < elementsToSign.getLength (); i++)
      {
        final Element elementToSign = (Element) elementsToSign.item (i);
        Assert.assertNotNull (elementToSign);
        final String id = UUID.randomUUID ().toString ();
        elementToSign.setAttributeNS (null, "Id", id);
        elementToSign.setIdAttributeNS (null, "Id", true);

        final Transforms transforms = new Transforms (document);
        transforms.addTransform (CanonicalizationMethod.EXCLUSIVE);
        sig.addDocument ("#" + id, transforms, DigestMethod.SHA1);
      }
    }

    sig.sign (signingKey);

    final String expression = "//ds:Signature[1]";
    final Element sigElement = (Element) xpath.evaluate (expression, document, XPathConstants.NODE);
    Assert.assertNotNull (sigElement);

    if (signingCert != null)
    {
      sig.addKeyInfo (signingCert);
    }
  }

  /*
   * Verify the document using the DOM API of Apache Santuario - XML Security
   * for Java. It finds a list of QNames via XPath and uses the DOM API to mark
   * them as having an "Id".
   */
  public static void verifyUsingDOM (final Document document,
                                     final List <QName> namesToSign,
                                     final X509Certificate cert) throws Exception
  {
    final XPathFactory xpf = XPathFactory.newInstance ();
    final XPath xpath = xpf.newXPath ();
    xpath.setNamespaceContext (_createNamespaceContext ());

    // Find the Signature Element
    String expression = "//dsig:Signature[1]";
    final Element sigElement = (Element) xpath.evaluate (expression, document, XPathConstants.NODE);
    Assert.assertNotNull (sigElement);

    for (final QName nameToSign : namesToSign)
    {
      expression = "//*[local-name()='" + nameToSign.getLocalPart () + "']";
      final Element signedElement = (Element) xpath.evaluate (expression, document, XPathConstants.NODE);
      Assert.assertNotNull (signedElement);
      signedElement.setIdAttributeNS (null, "Id", true);
    }

    final XMLSignature signature = new XMLSignature (sigElement, "");

    // Check we have a KeyInfo
    final KeyInfo ki = signature.getKeyInfo ();
    Assert.assertNotNull (ki);

    // Check the Signature value
    Assert.assertTrue (signature.checkSignatureValue (cert));
  }

  /*
   * Sign the document using the StAX API of Apache Santuario - XML Security for
   * Java.
   */
  public static ByteArrayOutputStream signUsingStAX (final InputStream inputStream,
                                                     final List <QName> namesToSign,
                                                     @SuppressWarnings ("unused") final String algorithm,
                                                     final Key signingKey,
                                                     final X509Certificate signingCert) throws Exception
  {
    // Set up the Configuration
    final XMLSecurityProperties properties = new XMLSecurityProperties ();
    final ICommonsList <XMLSecurityConstants.Action> actions = new CommonsArrayList<> ();
    actions.add (XMLSecurityConstants.SIGNATURE);
    properties.setActions (actions);

    properties.setSignatureCerts (new X509Certificate [] { signingCert });
    properties.setSignatureKey (signingKey);
    properties.setSignatureKeyIdentifier (SecurityTokenConstants.KeyIdentifier_X509KeyIdentifier);

    for (final QName nameToSign : namesToSign)
    {
      final SecurePart securePart = new SecurePart (nameToSign, SecurePart.Modifier.Content);
      properties.addSignaturePart (securePart);
    }

    final OutboundXMLSec aOutboundXMLSec = XMLSec.getOutboundXMLSec (properties);
    final ByteArrayOutputStream aBAOS = new ByteArrayOutputStream ();
    final XMLStreamWriter xmlStreamWriter = aOutboundXMLSec.processOutMessage (aBAOS, StandardCharsets.UTF_8.name ());

    final XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance ();
    final XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader (inputStream);

    XmlReaderToWriter.writeAll (xmlStreamReader, xmlStreamWriter);
    xmlStreamWriter.close ();

    return aBAOS;
  }

  /*
   * Verify the document using the StAX API of Apache Santuario - XML Security
   * for Java.
   */
  public static void verifyUsingStAX (final InputStream inputStream,
                                      final List <QName> namesToSign,
                                      final X509Certificate cert) throws Exception
  {
    // Set up the Configuration
    final XMLSecurityProperties properties = new XMLSecurityProperties ();
    final ICommonsList <XMLSecurityConstants.Action> actions = new CommonsArrayList<> ();
    actions.add (XMLSecurityConstants.SIGNATURE);
    properties.setActions (actions);

    properties.setSignatureVerificationKey (cert.getPublicKey ());

    final InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec (properties);

    final XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance ();
    final XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader (inputStream);

    final TestSecurityEventListener eventListener = new TestSecurityEventListener ();
    final XMLStreamReader securityStreamReader = inboundXMLSec.processInMessage (xmlStreamReader, null, eventListener);

    while (securityStreamReader.hasNext ())
    {
      securityStreamReader.next ();
    }
    xmlStreamReader.close ();
    inputStream.close ();

    // Check that what we were expecting to be signed was actually signed
    final List <SignedElementSecurityEvent> signedElementEvents = eventListener.getSecurityEvents (SecurityEventConstants.SignedElement);
    Assert.assertNotNull (signedElementEvents);

    for (final QName nameToSign : namesToSign)
    {
      boolean found = false;
      for (final SignedElementSecurityEvent signedElement : signedElementEvents)
      {
        if (signedElement.isSigned () && nameToSign.equals (getSignedQName (signedElement.getElementPath ())))
        {
          found = true;
          break;
        }
      }
      Assert.assertTrue (found);
    }

    // Check Signing cert
    final X509TokenSecurityEvent tokenEvent = (X509TokenSecurityEvent) eventListener.getSecurityEvent (SecurityEventConstants.X509Token);
    Assert.assertNotNull (tokenEvent);

    Assert.assertTrue (tokenEvent.getSecurityToken () instanceof X509SecurityToken);
    final X509SecurityToken x509SecurityToken = (X509SecurityToken) tokenEvent.getSecurityToken ();
    Assert.assertEquals (x509SecurityToken.getX509Certificates ()[0], cert);
  }

  private static QName getSignedQName (final List <QName> qnames)
  {
    return CollectionHelper.getLastElement (qnames);
  }
}
