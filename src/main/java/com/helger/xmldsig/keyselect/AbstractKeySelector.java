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
package com.helger.xmldsig.keyselect;

import javax.annotation.Nonnull;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.dsig.SignatureMethod;

/**
 * Base class for {@link KeySelector} implementations.
 * 
 * @author Philip Helger
 */
public abstract class AbstractKeySelector extends KeySelector
{
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
  protected static boolean algorithmEquals (@Nonnull final String sAlgURI, @Nonnull final String sAlgName)
  {
    if (sAlgName.equalsIgnoreCase ("DSA"))
      return sAlgURI.equalsIgnoreCase (SignatureMethod.DSA_SHA1);
    if (sAlgName.equalsIgnoreCase ("RSA"))
      return sAlgURI.equalsIgnoreCase (SignatureMethod.RSA_SHA1);
    if (sAlgName.equalsIgnoreCase ("EC"))
      return sAlgURI.equalsIgnoreCase ("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
    return false;
  }
}
