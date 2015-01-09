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

import java.security.Security;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;
import javax.xml.crypto.dsig.XMLSignatureFactory;

import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.apache.xml.security.Init;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * General setup for XMLDSig handling
 *
 * @author Philip Helger
 */
@Immutable
public final class XMLDSigSetup
{
  public static final String ELEMENT_SIGNATURE = "Signature";

  static
  {
    // Init Santuario
    Init.init ();

    // Required for SHA256withECDSA Signature
    Security.addProvider (new BouncyCastleProvider ());
  }

  private XMLDSigSetup ()
  {}

  @Nonnull
  public static XMLSignatureFactory getXMLSignatureFactory ()
  {
    return XMLSignatureFactory.getInstance ("DOM", new XMLDSigRI ());
  }
}
