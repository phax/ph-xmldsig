/*
 * Copyright (C) 2014-2024 Philip Helger (www.helger.com)
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
package com.helger.xmldsig.keyselect;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.annotation.Nonnull;
import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;

import com.helger.security.keystore.ConstantKeySelectorResult;

/**
 * Simple key selector, using the first {@link X509Certificate} contained in the
 * signature to be verified.
 *
 * @author Philip Helger
 */
public final class ContainedX509KeySelector extends AbstractKeySelector
{
  @Override
  @Nonnull
  public KeySelectorResult select (@Nonnull final KeyInfo aKeyInfo,
                                   final KeySelector.Purpose aPurpose,
                                   @Nonnull final AlgorithmMethod aMethod,
                                   final XMLCryptoContext aContext) throws KeySelectorException
  {
    for (final Object aKeyInfoElement : aKeyInfo.getContent ())
    {
      final XMLStructure aXMLStructure = (XMLStructure) aKeyInfoElement;
      if (aXMLStructure instanceof X509Data)
      {
        // We found a certificate
        final X509Data x509Data = (X509Data) aXMLStructure;
        for (final Object aX509Element : x509Data.getContent ())
        {
          if (aX509Element instanceof X509Certificate)
          {
            final X509Certificate aCert = (X509Certificate) aX509Element;
            final PublicKey aPublicKey = aCert.getPublicKey ();
            // Make sure the algorithm is compatible
            // with the method.
            if (algorithmEquals (aMethod.getAlgorithm (), aPublicKey.getAlgorithm ()))
              return new ConstantKeySelectorResult (aPublicKey);
          }
        }
      }
    }
    throw new KeySelectorException ("No key found!");
  }
}
