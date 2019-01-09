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
package com.helger.xmldsig.keyselect;

import javax.annotation.Nonnull;
import javax.xml.crypto.KeySelector;

import org.apache.xml.security.signature.XMLSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helger.commons.string.ToStringGenerator;

/**
 * Base class for {@link KeySelector} implementations.
 *
 * @author Philip Helger
 */
public abstract class AbstractKeySelector extends KeySelector
{
  private static final Logger LOGGER = LoggerFactory.getLogger (AbstractKeySelector.class);

  /**
   * Checks if a JCA/JCE public key algorithm name is compatible with the
   * specified signature algorithm URI.
   *
   * @param sAlgURI
   *        The requested algorithm URI.
   * @param sAlgName
   *        The provided algorithm name from a public key.
   * @return <code>true</code> if the name matches the URI.
   */
  public static boolean algorithmEquals (@Nonnull final String sAlgURI, @Nonnull final String sAlgName)
  {
    if (sAlgName.equalsIgnoreCase ("DSA"))
    {
      return sAlgURI.equalsIgnoreCase (XMLSignature.ALGO_ID_SIGNATURE_DSA) ||
             sAlgURI.equalsIgnoreCase (XMLSignature.ALGO_ID_SIGNATURE_DSA_SHA256);
    }
    if (sAlgName.equalsIgnoreCase ("RSA"))
    {
      return sAlgURI.equalsIgnoreCase (XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1) ||
             sAlgURI.equalsIgnoreCase (XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1_MGF1) ||
             sAlgURI.equalsIgnoreCase (XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA224) ||
             sAlgURI.equalsIgnoreCase (XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA224_MGF1) ||
             sAlgURI.equalsIgnoreCase (XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256) ||
             sAlgURI.equalsIgnoreCase (XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1) ||
             sAlgURI.equalsIgnoreCase (XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384) ||
             sAlgURI.equalsIgnoreCase (XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384_MGF1) ||
             sAlgURI.equalsIgnoreCase (XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512) ||
             sAlgURI.equalsIgnoreCase (XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512_MGF1) ||
             sAlgURI.equalsIgnoreCase (XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_224_MGF1) ||
             sAlgURI.equalsIgnoreCase (XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_256_MGF1) ||
             sAlgURI.equalsIgnoreCase (XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_384_MGF1) ||
             sAlgURI.equalsIgnoreCase (XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_512_MGF1);
    }
    if (sAlgName.equalsIgnoreCase ("EC"))
    {
      return sAlgURI.equalsIgnoreCase (XMLSignature.ALGO_ID_SIGNATURE_ECDSA_RIPEMD160) ||
             sAlgURI.equalsIgnoreCase (XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA1) ||
             sAlgURI.equalsIgnoreCase (XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA224) ||
             sAlgURI.equalsIgnoreCase (XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256) ||
             sAlgURI.equalsIgnoreCase (XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA384) ||
             sAlgURI.equalsIgnoreCase (XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA512);
    }

    LOGGER.warn ("Algorithm mismatch between JCA/JCE public key algorithm name ('" +
                 sAlgName +
                 "') and signature algorithm URI ('" +
                 sAlgURI +
                 "')");
    return false;
  }

  @Override
  public String toString ()
  {
    return new ToStringGenerator (this).getToString ();
  }
}
