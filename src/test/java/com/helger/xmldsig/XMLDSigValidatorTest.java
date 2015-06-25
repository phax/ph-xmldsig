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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;

import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import com.helger.commons.io.file.iterate.FileSystemRecursiveIterator;
import com.helger.commons.io.resource.ClassPathResource;
import com.helger.commons.xml.sax.DoNothingSAXErrorHandler;
import com.helger.commons.xml.serialize.read.DOMReader;
import com.helger.commons.xml.serialize.read.DOMReaderSettings;

/**
 * Test class for class {@link XMLDSigValidator}
 *
 * @author Philip Helger
 */
public final class XMLDSigValidatorTest
{
  private static final Logger s_aLogger = LoggerFactory.getLogger (XMLDSigValidatorTest.class);

  @Ignore
  @Test
  public void testFindAllValidatableFiles ()
  {
    final DOMReaderSettings aDOMRS = new DOMReaderSettings ().setErrorHandler (new DoNothingSAXErrorHandler ());
    for (final File aFile : new FileSystemRecursiveIterator ("src/test/resources"))
      if (aFile.isFile () && aFile.getName ().endsWith (".xml"))
      {
        // Read document
        Document aDoc = null;
        try
        {
          aDoc = DOMReader.readXMLDOM (aFile, aDOMRS);
          assertNotNull (aDoc);
        }
        catch (final SAXException ex)
        {
          // fall through
        }
        if (aDoc == null)
          continue;

        // Validate the signature
        try
        {
          if (XMLDSigValidator.validateSignature (aDoc).isValid ())
            System.out.println ("OK: " + aFile.getAbsolutePath ());
        }
        catch (final Exception ex)
        {}
      }
  }

  @Test
  public void testSign () throws Exception
  {
    for (final String sPath : new String [] { "valid6-signed.xml",
                                             "mesonic1.xml",
                                             "mesonic2.xml",
                                             "valid_and_signed.xml",
                                             // "ebinterface4-signed.xml",
                                             "Rechnung-R_00156_3_00.xml" })
    {
      s_aLogger.info (sPath);

      // Read document
      final Document aDoc = DOMReader.readXMLDOM (new ClassPathResource ("xml-signed/" + sPath));
      assertNotNull (aDoc);

      // Validate the signature
      assertTrue (XMLDSigValidator.validateSignature (aDoc).isValid ());

      if (!aDoc.getDocumentElement ().getLocalName ().equals (XMLDSigSetup.ELEMENT_SIGNATURE))
      {
        // Modify the document
        aDoc.getDocumentElement ().appendChild (aDoc.createTextNode ("text"));

        // Validate again - must fail
        assertTrue (XMLDSigValidator.validateSignature (aDoc).isInvalid ());
      }
    }
  }
}
