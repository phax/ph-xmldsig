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

  public static void write (final XMLStreamReader xmlr, final XMLStreamWriter writer) throws XMLStreamException
  {
    switch (xmlr.getEventType ())
    {
      case XMLStreamConstants.START_ELEMENT:
        final String localName = xmlr.getLocalName ();
        final String namespaceURI = xmlr.getNamespaceURI ();
        if (namespaceURI != null && namespaceURI.length () > 0)
        {
          final String prefix = xmlr.getPrefix ();
          if (prefix != null)
            writer.writeStartElement (prefix, localName, namespaceURI);
          else
            writer.writeStartElement (namespaceURI, localName);
        }
        else
        {
          writer.writeStartElement (localName);
        }

        for (int i = 0, len = xmlr.getNamespaceCount (); i < len; i++)
        {
          final String prefix = xmlr.getNamespacePrefix (i);
          if (prefix == null)
            writer.writeDefaultNamespace (xmlr.getNamespaceURI (i));
          else
            writer.writeNamespace (prefix, xmlr.getNamespaceURI (i));
        }

        for (int i = 0, len = xmlr.getAttributeCount (); i < len; i++)
        {
          final String attUri = xmlr.getAttributeNamespace (i);

          if (attUri != null && attUri.length () > 0)
          {
            final String prefix = xmlr.getAttributePrefix (i);
            if (prefix != null)
              writer.writeAttribute (prefix, attUri, xmlr.getAttributeLocalName (i), xmlr.getAttributeValue (i));
            else
              writer.writeAttribute (attUri, xmlr.getAttributeLocalName (i), xmlr.getAttributeValue (i));
          }
          else
          {
            writer.writeAttribute (xmlr.getAttributeLocalName (i), xmlr.getAttributeValue (i));
          }
        }
        break;
      case XMLStreamConstants.END_ELEMENT:
        writer.writeEndElement ();
        break;
      case XMLStreamConstants.SPACE:
      case XMLStreamConstants.CHARACTERS:
        final char [] text = new char [xmlr.getTextLength ()];
        xmlr.getTextCharacters (0, text, 0, xmlr.getTextLength ());
        writer.writeCharacters (text, 0, text.length);
        break;
      case XMLStreamConstants.PROCESSING_INSTRUCTION:
        writer.writeProcessingInstruction (xmlr.getPITarget (), xmlr.getPIData ());
        break;
      case XMLStreamConstants.CDATA:
        writer.writeCData (xmlr.getText ());
        break;
      case XMLStreamConstants.COMMENT:
        writer.writeComment (xmlr.getText ());
        break;
      case XMLStreamConstants.ENTITY_REFERENCE:
        writer.writeEntityRef (xmlr.getLocalName ());
        break;
      case XMLStreamConstants.START_DOCUMENT:
        final String encoding = xmlr.getCharacterEncodingScheme ();
        final String version = xmlr.getVersion ();

        if (encoding != null && version != null)
          writer.writeStartDocument (encoding, version);
        else
          if (version != null)
            writer.writeStartDocument (xmlr.getVersion ());
        break;
      case XMLStreamConstants.END_DOCUMENT:
        writer.writeEndDocument ();
        break;
      case XMLStreamConstants.DTD:
        writer.writeDTD (xmlr.getText ());
        break;
    }
  }
}
