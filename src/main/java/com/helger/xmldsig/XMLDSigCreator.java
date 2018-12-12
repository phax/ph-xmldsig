/**
 * Copyright (C) 2014-2018 Philip Helger (www.helger.com)
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

import java.security.KeyException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;
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

import com.helger.commons.ValueEnforcer;
import com.helger.commons.annotation.OverrideOnDemand;
import com.helger.commons.annotation.ReturnsMutableCopy;
import com.helger.commons.collection.impl.CommonsArrayList;
import com.helger.commons.collection.impl.ICommonsList;

/**
 * Utility class for applying a signature to ebInterface documents.
 *
 * @author Philip Helger
 */
@Immutable
public class XMLDSigCreator
{
  public static final String DEFAULT_NS_PREFIX = "dsig";

  private final XMLSignatureFactory m_aSignatureFactory;

  public XMLDSigCreator ()
  {
    // Create a DOM XMLSignatureFactory that will be used to generate the
    // enveloped signature.
    m_aSignatureFactory = XMLDSigSetup.getXMLSignatureFactory ();
  }

  @Nonnull
  public final XMLSignatureFactory getSignatureFactory ()
  {
    return m_aSignatureFactory;
  }

  @Nullable
  @OverrideOnDemand
  protected String getDefaultReferenceURI ()
  {
    // "" means sign the whole document
    return "";
  }

  @Nonnull
  @OverrideOnDemand
  protected String getDigestMethod () throws Exception
  {
    return DigestMethod.SHA1;
  }

  @Nonnull
  @OverrideOnDemand
  protected DigestMethod createDigestMethod () throws Exception
  {
    return m_aSignatureFactory.newDigestMethod (getDigestMethod (), (DigestMethodParameterSpec) null);
  }

  @Nonnull
  @OverrideOnDemand
  protected String getDefaultTransform () throws Exception
  {
    return Transform.ENVELOPED;
  }

  @Nonnull
  @OverrideOnDemand
  protected Transform createDefaultTransform () throws Exception
  {
    return m_aSignatureFactory.newTransform (getDefaultTransform (), (TransformParameterSpec) null);
  }

  @Nonnull
  @OverrideOnDemand
  protected List <Transform> createTransformList () throws Exception
  {
    return new CommonsArrayList <> (createDefaultTransform ());
  }

  @Nullable
  @OverrideOnDemand
  protected String getDefaultReferenceType () throws Exception
  {
    return null;
  }

  @Nullable
  @OverrideOnDemand
  protected String getDefaultReferenceID () throws Exception
  {
    return null;
  }

  @Nonnull
  @ReturnsMutableCopy
  protected Reference createDefaultReference () throws Exception
  {
    // Create a Reference to the enveloped document (we are signing the whole
    // document, so a URI of "" signifies that, and also specify the SHA1 digest
    // algorithm and the ENVELOPED Transform)
    return m_aSignatureFactory.newReference (getDefaultReferenceURI (),
                                             createDigestMethod (),
                                             createTransformList (),
                                             getDefaultReferenceType (),
                                             getDefaultReferenceID ());
  }

  @Nonnull
  @ReturnsMutableCopy
  protected ICommonsList <Reference> createReferenceList () throws Exception
  {
    final ICommonsList <Reference> ret = new CommonsArrayList <> ();
    ret.addIfNotNull (createDefaultReference ());
    return ret;
  }

  @Nonnull
  @OverrideOnDemand
  protected String getCanonicalizationMethod () throws Exception
  {
    return CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS;
  }

  @Nonnull
  @OverrideOnDemand
  protected CanonicalizationMethod createCanonicalizationMethod () throws Exception
  {
    return m_aSignatureFactory.newCanonicalizationMethod (getCanonicalizationMethod (), (C14NMethodParameterSpec) null);
  }

  @Nonnull
  @OverrideOnDemand
  protected String getSignatureMethod () throws Exception
  {
    return SignatureMethod.RSA_SHA1;
  }

  @Nonnull
  @OverrideOnDemand
  protected SignatureMethod createSignatureMethod () throws Exception
  {
    return m_aSignatureFactory.newSignatureMethod (getSignatureMethod (), (SignatureMethodParameterSpec) null);
  }

  @Nonnull
  public SignedInfo createSignedInfo () throws Exception
  {
    // Create the SignedInfo.
    return m_aSignatureFactory.newSignedInfo (createCanonicalizationMethod (),
                                              createSignatureMethod (),
                                              createReferenceList ());
  }

  @Nonnull
  public KeyInfo createKeyInfo (@Nonnull final X509Certificate aCertificate) throws KeyException
  {
    // Create the KeyInfo containing the X509Data.
    final KeyInfoFactory aKeyInfoFactory = m_aSignatureFactory.getKeyInfoFactory ();

    // The X509 certificate subject name and the certificate itself
    final ICommonsList <Object> aX509Content = new CommonsArrayList <> (aCertificate.getSubjectX500Principal ()
                                                                                    .getName (),
                                                                        aCertificate);
    final X509Data aX509Data = aKeyInfoFactory.newX509Data (aX509Content);

    // The public key itself
    final KeyValue aKeyValue = aKeyInfoFactory.newKeyValue (aCertificate.getPublicKey ());

    // Collect certificate and key value in key info
    return aKeyInfoFactory.newKeyInfo (new CommonsArrayList <> (aX509Data, aKeyValue));
  }

  @Nonnull
  @OverrideOnDemand
  public XMLSignature createXMLSignature (@Nonnull final X509Certificate aCertificate) throws Exception
  {
    return createXMLSignature (aCertificate, null, null, null);
  }

  @Nonnull
  @OverrideOnDemand
  public XMLSignature createXMLSignature (@Nonnull final X509Certificate aCertificate,
                                          @Nullable final List <?> aObjects,
                                          @Nullable final String sID,
                                          @Nullable final String sSignatureValueID) throws Exception
  {
    ValueEnforcer.notNull (aCertificate, "certificate");

    // Create the SignedInfo.
    final SignedInfo aSignedInfo = createSignedInfo ();

    // Collect certificate and key value in key info
    final KeyInfo aKeyInfo = createKeyInfo (aCertificate);

    // Create the XMLSignature, but don't sign it yet.
    return m_aSignatureFactory.newXMLSignature (aSignedInfo, aKeyInfo, aObjects, sID, sSignatureValueID);
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
   * @see #createXMLSignature(X509Certificate)
   */
  public void applyXMLDSigAsFirstChild (@Nonnull final PrivateKey aPrivateKey,
                                        @Nonnull final X509Certificate aCertificate,
                                        @Nonnull final Document aDocument) throws Exception
  {
    ValueEnforcer.notNull (aPrivateKey, "privateKey");
    ValueEnforcer.notNull (aCertificate, "certificate");
    ValueEnforcer.notNull (aDocument, "document");
    ValueEnforcer.notNull (aDocument.getDocumentElement (), "Document is missing a document element");
    if (aDocument.getDocumentElement ().getChildNodes ().getLength () == 0)
      throw new IllegalArgumentException ("Document element has no children!");

    // Check that the document does not contain another Signature element
    final NodeList aNodeList = aDocument.getElementsByTagNameNS (XMLSignature.XMLNS, XMLDSigSetup.ELEMENT_SIGNATURE);
    if (aNodeList.getLength () > 0)
      throw new IllegalArgumentException ("Document already contains an XMLDSig Signature element!");

    // Create the XMLSignature, but don't sign it yet.
    final XMLSignature aXMLSignature = createXMLSignature (aCertificate);

    // Create a DOMSignContext and specify the RSA PrivateKey and
    // location of the resulting XMLSignature's parent element.
    // -> The signature is always the first child element of the document
    // element for ebInterface
    final DOMSignContext aDOMSignContext = new DOMSignContext (aPrivateKey,
                                                               aDocument.getDocumentElement (),
                                                               aDocument.getDocumentElement ().getFirstChild ());

    // The namespace prefix to be used for the signed XML
    aDOMSignContext.setDefaultNamespacePrefix (DEFAULT_NS_PREFIX);

    // Marshal, generate, and sign the enveloped signature.
    aXMLSignature.sign (aDOMSignContext);
  }
}
