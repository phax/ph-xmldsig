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
package com.helger.xmldsig.coheigea;

// Revised from xmlbeans

import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

public final class XmlReaderToWriter
{
  private XmlReaderToWriter ()
  {}

  public static void writeAll (final XMLStreamReader xmlr, final XMLStreamWriter writer) throws XMLStreamException
  {
    while (xmlr.hasNext ())
    {
      xmlr.next ();
      write (xmlr, writer);
    }
    // write(xmlr, writer); // write the last element
    writer.flush ();
  }

  public static void write (final XMLStreamReader xmlr, final XMLStreamWriter aWriter) throws XMLStreamException
  {
    switch (xmlr.getEventType ())
    {
      case XMLStreamConstants.START_ELEMENT:
        final String sLocalName = xmlr.getLocalName ();
        final String sNamespaceURI = xmlr.getNamespaceURI ();
        if (sNamespaceURI != null && sNamespaceURI.length () > 0)
        {
          final String sPrefix = xmlr.getPrefix ();
          if (sPrefix != null)
            aWriter.writeStartElement (sPrefix, sLocalName, sNamespaceURI);
          else
            aWriter.writeStartElement (sNamespaceURI, sLocalName);
        }
        else
        {
          aWriter.writeStartElement (sLocalName);
        }

        for (int i = 0, len = xmlr.getNamespaceCount (); i < len; i++)
        {
          final String sPrefix = xmlr.getNamespacePrefix (i);
          if (sPrefix == null)
            aWriter.writeDefaultNamespace (xmlr.getNamespaceURI (i));
          else
            aWriter.writeNamespace (sPrefix, xmlr.getNamespaceURI (i));
        }

        for (int i = 0, len = xmlr.getAttributeCount (); i < len; i++)
        {
          final String sAttUri = xmlr.getAttributeNamespace (i);
          if (sAttUri != null && sAttUri.length () > 0)
          {
            final String sPrefix = xmlr.getAttributePrefix (i);
            if (sPrefix != null)
              aWriter.writeAttribute (sPrefix, sAttUri, xmlr.getAttributeLocalName (i), xmlr.getAttributeValue (i));
            else
              aWriter.writeAttribute (sAttUri, xmlr.getAttributeLocalName (i), xmlr.getAttributeValue (i));
          }
          else
          {
            aWriter.writeAttribute (xmlr.getAttributeLocalName (i), xmlr.getAttributeValue (i));
          }
        }
        break;
      case XMLStreamConstants.END_ELEMENT:
        aWriter.writeEndElement ();
        break;
      case XMLStreamConstants.SPACE:
      case XMLStreamConstants.CHARACTERS:
        final char [] aTextChars = new char [xmlr.getTextLength ()];
        xmlr.getTextCharacters (0, aTextChars, 0, xmlr.getTextLength ());
        aWriter.writeCharacters (aTextChars, 0, aTextChars.length);
        break;
      case XMLStreamConstants.PROCESSING_INSTRUCTION:
        aWriter.writeProcessingInstruction (xmlr.getPITarget (), xmlr.getPIData ());
        break;
      case XMLStreamConstants.CDATA:
        aWriter.writeCData (xmlr.getText ());
        break;
      case XMLStreamConstants.COMMENT:
        aWriter.writeComment (xmlr.getText ());
        break;
      case XMLStreamConstants.ENTITY_REFERENCE:
        aWriter.writeEntityRef (xmlr.getLocalName ());
        break;
      case XMLStreamConstants.START_DOCUMENT:
        final String sEncoding = xmlr.getCharacterEncodingScheme ();
        final String sVersion = xmlr.getVersion ();

        if (sEncoding != null && sVersion != null)
          aWriter.writeStartDocument (sEncoding, sVersion);
        else
          if (sVersion != null)
            aWriter.writeStartDocument (xmlr.getVersion ());
        break;
      case XMLStreamConstants.END_DOCUMENT:
        aWriter.writeEndDocument ();
        break;
      case XMLStreamConstants.DTD:
        aWriter.writeDTD (xmlr.getText ());
        break;
    }
  }
}
