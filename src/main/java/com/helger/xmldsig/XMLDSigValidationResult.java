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

import java.io.Serializable;
import java.util.List;

import javax.annotation.Nonnull;

import com.helger.commons.ValueEnforcer;
import com.helger.commons.annotation.Nonempty;
import com.helger.commons.annotation.ReturnsMutableCopy;
import com.helger.commons.collection.impl.CommonsArrayList;
import com.helger.commons.collection.impl.ICommonsList;
import com.helger.commons.state.IValidityIndicator;
import com.helger.commons.string.ToStringGenerator;

/**
 * This class encapsulates the results of XML DSig validation.
 *
 * @author Philip Helger
 */
public class XMLDSigValidationResult implements IValidityIndicator, Serializable
{
  private final boolean m_bValidOverall;
  private final boolean m_bSignatureValid;
  private final ICommonsList <Integer> m_aInvalidReferences;

  private XMLDSigValidationResult ()
  {
    m_bValidOverall = true;
    m_bSignatureValid = true;
    m_aInvalidReferences = null;
  }

  private XMLDSigValidationResult (final boolean bSignatureValid)
  {
    m_bValidOverall = false;
    m_bSignatureValid = bSignatureValid;
    m_aInvalidReferences = null;
  }

  public XMLDSigValidationResult (@Nonnull @Nonempty final List <Integer> aInvalidReferences)
  {
    ValueEnforcer.notEmpty (aInvalidReferences, "InvalidReferences");

    m_bValidOverall = false;
    m_bSignatureValid = true;
    m_aInvalidReferences = new CommonsArrayList <> (aInvalidReferences);
  }

  public boolean isValid ()
  {
    return m_bValidOverall;
  }

  /**
   * @return May only be <code>false</code> , if the overall validity is
   *         <code>false</code>
   */
  public boolean isSignatureValid ()
  {
    return m_bSignatureValid;
  }

  /**
   * @return A list with all invalid reference indices. Never <code>null</code>
   *         but may be empty in case of success.
   */
  @Nonnull
  @ReturnsMutableCopy
  public ICommonsList <Integer> getInvalidReferenceIndices ()
  {
    return new CommonsArrayList <> (m_aInvalidReferences);
  }

  @Override
  public String toString ()
  {
    return new ToStringGenerator (this).append ("valid", m_bValidOverall)
                                       .append ("signatureValid", m_bSignatureValid)
                                       .append ("invalidReferences", m_aInvalidReferences)
                                       .getToString ();
  }

  /**
   * Successful validation
   *
   * @return Result object
   */
  @Nonnull
  public static XMLDSigValidationResult createSuccess ()
  {
    return new XMLDSigValidationResult ();
  }

  /**
   * An invalid signature. The cryptographic verification of the signature
   * failed. This can be caused by an incorrect validation key or a change to
   * the SignedInfo contents since the signature was generated.
   *
   * @return Result object
   */
  @Nonnull
  public static XMLDSigValidationResult createSignatureError ()
  {
    return new XMLDSigValidationResult (false);
  }

  /**
   * An invalid reference or references. The verification of the digest of a
   * reference failed. This can be caused by a change to the referenced data
   * since the signature was generated.
   *
   * @param aInvalidReferences
   *        The indices to the invalid references.
   * @return Result object
   */
  @Nonnull
  public static XMLDSigValidationResult createReferenceErrors (@Nonnull @Nonempty final List <Integer> aInvalidReferences)
  {
    return new XMLDSigValidationResult (aInvalidReferences);
  }
}
