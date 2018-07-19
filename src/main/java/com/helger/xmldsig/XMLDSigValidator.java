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

import java.util.Iterator;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.helger.commons.ValueEnforcer;
import com.helger.commons.collection.impl.CommonsArrayList;
import com.helger.commons.collection.impl.ICommonsList;
import com.helger.xmldsig.keyselect.X509KeySelector;

/**
 * Utility class for validating XML DSig within ebInterface documents.
 *
 * @author Philip Helger
 */
@Immutable
public final class XMLDSigValidator
{
  private static final Logger LOGGER = LoggerFactory.getLogger (XMLDSigValidator.class);

  private XMLDSigValidator ()
  {}

  public static boolean containsSignature (@Nonnull final Document aDoc)
  {
    ValueEnforcer.notNull (aDoc, "Document");

    final NodeList aSignatureNL = aDoc.getElementsByTagNameNS (XMLSignature.XMLNS, XMLDSigSetup.ELEMENT_SIGNATURE);
    return aSignatureNL.getLength () > 0;
  }

  @Nonnull
  public static XMLDSigValidationResult validateSignature (@Nonnull final Document aDoc) throws XMLSignatureException
  {
    return validateSignature (aDoc, new X509KeySelector ());
  }

  @Nonnull
  public static XMLDSigValidationResult validateSignature (@Nonnull final Document aDoc,
                                                           @Nonnull final KeySelector aKeySelector) throws XMLSignatureException
  {
    ValueEnforcer.notNull (aDoc, "Document");
    ValueEnforcer.notNull (aKeySelector, "KeySelector");

    // Find Signature element.
    final NodeList aSignatureNL = aDoc.getElementsByTagNameNS (XMLSignature.XMLNS, XMLDSigSetup.ELEMENT_SIGNATURE);
    if (aSignatureNL.getLength () != 1)
      throw new IllegalArgumentException ("Cannot find exactly one Signature element");
    final Element aSignatureElement = (Element) aSignatureNL.item (0);

    // Create a DOM XMLSignatureFactory that will be used to validate the
    // enveloped signature.
    final XMLSignatureFactory aSignatureFactory = XMLDSigSetup.getXMLSignatureFactory ();

    // Create a DOMValidateContext and specify a KeySelector
    // and document context.
    final DOMValidateContext aValidationContext = new DOMValidateContext (aKeySelector, aSignatureElement);
    // aValidationContext.setProperty
    // ("org.jcp.xml.dsig.internal.dom.SignatureProvider", new XMLDSigRI ());

    // Unmarshal the XMLSignature.
    XMLSignature aSignature;
    try
    {
      aSignature = aSignatureFactory.unmarshalXMLSignature (aValidationContext);
    }
    catch (final MarshalException ex)
    {
      LOGGER.error ("Failed to read XML signature: " + ex.getClass ().getName () + " - " + ex.getMessage ());
      return XMLDSigValidationResult.createSignatureError ();
    }

    // Validate the XMLSignature.
    if (aSignature.validate (aValidationContext))
      return XMLDSigValidationResult.createSuccess ();

    // Core validation failed. Check the signature value.
    if (!aSignature.getSignatureValue ().validate (aValidationContext))
      return XMLDSigValidationResult.createSignatureError ();

    // Check the validation status of each Reference.
    final ICommonsList <Integer> aInvalidReferences = new CommonsArrayList <> ();
    final Iterator <?> it = aSignature.getSignedInfo ().getReferences ().iterator ();
    for (int nIndex = 0; it.hasNext (); nIndex++)
    {
      final Reference aReference = (Reference) it.next ();
      if (!aReference.validate (aValidationContext))
      {
        aInvalidReferences.add (Integer.valueOf (nIndex));
      }
    }
    return XMLDSigValidationResult.createReferenceErrors (aInvalidReferences);
  }
}
