/**
 * Copyright (C) 2014-2015 Philip Helger (www.helger.com)
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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.DigestMethodParameterSpec;
import javax.xml.crypto.dsig.spec.SignatureMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import com.helger.commons.annotations.OverrideOnDemand;
import com.helger.commons.collections.ContainerHelper;

/**
 * Utility class for applying a signature to ebInterface documents.
 * 
 * @author Philip Helger
 */
@Immutable
public class XMLDSigCreator
{
  public XMLDSigCreator ()
  {}

  @Nonnull
  @OverrideOnDemand
  protected DigestMethod createDigestMethod (@Nonnull final XMLSignatureFactory aSignatureFactory) throws Exception
  {
    return aSignatureFactory.newDigestMethod (DigestMethod.SHA1, (DigestMethodParameterSpec) null);
  }

  @Nonnull
  @OverrideOnDemand
  protected List <Transform> createTransformList (@Nonnull final XMLSignatureFactory aSignatureFactory) throws Exception
  {
    return ContainerHelper.<Transform> newUnmodifiableList (aSignatureFactory.newTransform (Transform.ENVELOPED,
                                                                                            (TransformParameterSpec) null));
  }

  @Nonnull
  @OverrideOnDemand
  protected CanonicalizationMethod createCanonicalizationMethod (@Nonnull final XMLSignatureFactory aSignatureFactory) throws Exception
  {
    return aSignatureFactory.newCanonicalizationMethod (CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
                                                        (C14NMethodParameterSpec) null);
  }

  @Nonnull
  @OverrideOnDemand
  protected SignatureMethod createSignatureMethod (@Nonnull final XMLSignatureFactory aSignatureFactory) throws Exception
  {
    return aSignatureFactory.newSignatureMethod (SignatureMethod.RSA_SHA1, (SignatureMethodParameterSpec) null);
  }

  /**
   * Apply an XMLDSig onto the passed document.
   * 
   * @param aPrivateKey
   *        The private key used for signing. May not be <code>null</code>.
   * @param aCertificate
   *        The certificate to be used. May not be <code>null</code>.
   * @param aDocument
   *        The document to be signed. The signature will always be the first
   *        child element of the document element. The document may not contains
   *        any disg:Signature element. This element is inserted manually.
   * @throws Exception
   *         In case something goes wrong
   */
  public void applyXMLDSig (@Nonnull final PrivateKey aPrivateKey,
                            @Nonnull final X509Certificate aCertificate,
                            @Nonnull final Document aDocument) throws Exception
  {
    if (aPrivateKey == null)
      throw new NullPointerException ("privateKey");
    if (aCertificate == null)
      throw new NullPointerException ("certificate");
    if (aDocument == null)
      throw new NullPointerException ("document");
    if (aDocument.getDocumentElement () == null)
      throw new IllegalArgumentException ("Document is missing a document element");
    if (aDocument.getDocumentElement ().getChildNodes ().getLength () == 0)
      throw new IllegalArgumentException ("Document element has no children!");

    // Check that the document does not contain another Signature element
    final NodeList aNodeList = aDocument.getElementsByTagNameNS (XMLSignature.XMLNS,
                                                                 XMLDSigSetup.ELEMENT_SIGNATURE);
    if (aNodeList.getLength () > 0)
      throw new IllegalArgumentException ("Document already contains an XMLDSig Signature element!");

    // Create a DOM XMLSignatureFactory that will be used to generate the
    // enveloped signature.
    final XMLSignatureFactory aSignatureFactory = XMLDSigSetup.getXMLSignatureFactory ();

    // Create a Reference to the enveloped document (we are signing the whole
    // document, so a URI of "" signifies that, and also specify the SHA1 digest
    // algorithm and the ENVELOPED Transform)
    final Reference aReference = aSignatureFactory.newReference ("",
                                                                 createDigestMethod (aSignatureFactory),
                                                                 createTransformList (aSignatureFactory),
                                                                 null,
                                                                 null);

    // Create the SignedInfo.
    final SignedInfo aSignedInfo = aSignatureFactory.newSignedInfo (createCanonicalizationMethod (aSignatureFactory),
                                                                    createSignatureMethod (aSignatureFactory),
                                                                    ContainerHelper.<Reference> newUnmodifiableList (aReference));

    // Create the KeyInfo containing the X509Data.
    final KeyInfoFactory aKeyInfoFactory = aSignatureFactory.getKeyInfoFactory ();
    // The X509 certificate
    final List <Object> aX509Content = new ArrayList <Object> ();
    aX509Content.add (aCertificate.getSubjectX500Principal ().getName ());
    aX509Content.add (aCertificate);
    final X509Data aX509Data = aKeyInfoFactory.newX509Data (aX509Content);

    // The public key itself
    final KeyValue aKeyValue = aKeyInfoFactory.newKeyValue (aCertificate.getPublicKey ());

    // Collect certificate and key value in key info
    final KeyInfo aKeyInfo = aKeyInfoFactory.newKeyInfo (ContainerHelper.<XMLStructure> newUnmodifiableList (aX509Data,
                                                                                                             aKeyValue));

    // Create the XMLSignature, but don't sign it yet.
    final XMLSignature aXMLSignature = aSignatureFactory.newXMLSignature (aSignedInfo, aKeyInfo);

    // Create a DOMSignContext and specify the RSA PrivateKey and
    // location of the resulting XMLSignature's parent element.
    // -> The signature is always the first child element of the document
    // element for ebInterface
    final DOMSignContext aDOMSignContext = new DOMSignContext (aPrivateKey,
                                                               aDocument.getDocumentElement (),
                                                               aDocument.getDocumentElement ().getFirstChild ());

    // The namespace prefix to be used for the signed XML
    aDOMSignContext.setDefaultNamespacePrefix ("dsig");

    // Marshal, generate, and sign the enveloped signature.
    aXMLSignature.sign (aDOMSignContext);
  }
}
