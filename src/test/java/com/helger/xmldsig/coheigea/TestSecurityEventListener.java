/*
 * Copyright (C) 2014-2025 Philip Helger (www.helger.com)
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

import java.util.List;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants.Event;
import org.apache.xml.security.stax.securityEvent.SecurityEventListener;

import com.helger.commons.collection.impl.CommonsArrayList;
import com.helger.commons.collection.impl.ICommonsList;

public final class TestSecurityEventListener implements SecurityEventListener
{
  private final ICommonsList <SecurityEvent> events = new CommonsArrayList <> ();

  @Override
  public void registerSecurityEvent (final SecurityEvent securityEvent) throws XMLSecurityException
  {
    events.add (securityEvent);
  }

  @SuppressWarnings ("unchecked")
  public <T> T getSecurityEvent (final Event securityEvent)
  {
    for (final SecurityEvent event : events)
      if (event.getSecurityEventType () == securityEvent)
        return (T) event;
    return null;
  }

  @SuppressWarnings ("unchecked")
  public <T> ICommonsList <T> getSecurityEvents (final Event securityEvent)
  {
    final ICommonsList <T> foundEvents = new CommonsArrayList <> ();
    for (final SecurityEvent event : events)
      if (event.getSecurityEventType () == securityEvent)
        foundEvents.add ((T) event);
    return foundEvents;
  }

  public List <SecurityEvent> getSecurityEvents ()
  {
    return events;
  }
}
