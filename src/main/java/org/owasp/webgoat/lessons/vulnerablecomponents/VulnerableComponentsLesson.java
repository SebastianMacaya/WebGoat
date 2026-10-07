/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.vulnerablecomponents;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.io.StringReader;
import java.util.HashSet;
import java.util.Set;
import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"vulnerable.hint"})
public class VulnerableComponentsLesson implements AssignmentEndpoint {

  @PostMapping("/VulnerableComponents/attack1")
  public @ResponseBody AttackResult completed(@RequestParam String payload) {
    try {
      ContactImpl contact = parseContact(payload);
      return failed(this).feedback("vulnerable-components.fromXML").feedbackArgs(contact).build();
    } catch (Exception ex) {
      return failed(this).feedback("vulnerable-components.close").output(ex.getMessage()).build();
    }
  }

  private ContactImpl parseContact(String payload) throws XMLStreamException {
    if (payload == null || payload.isBlank()) {
      throw new XMLStreamException("Contact XML is empty");
    }

    XMLInputFactory factory = XMLInputFactory.newFactory();
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
    factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(payload));
    try {
      if (reader.nextTag() != XMLStreamConstants.START_ELEMENT
          || !reader.getName().equals(new QName("contact"))
          || reader.getAttributeCount() != 0) {
        throw new XMLStreamException("Expected a contact element without attributes");
      }

      ContactImpl contact = new ContactImpl();
      Set<String> fields = new HashSet<>();
      while (reader.nextTag() == XMLStreamConstants.START_ELEMENT) {
        String field = reader.getLocalName();
        if (!reader.getName().getNamespaceURI().isEmpty()
            || reader.getAttributeCount() != 0
            || !fields.add(field)) {
          throw new XMLStreamException("Invalid contact field");
        }
        String value = reader.getElementText();
        switch (field) {
          case "id" -> contact.setId(Integer.valueOf(value.trim()));
          case "firstName" -> contact.setFirstName(value);
          case "lastName" -> contact.setLastName(value);
          case "email" -> contact.setEmail(value);
          default -> throw new XMLStreamException("Unexpected contact field: " + field);
        }
      }

      if (!reader.getName().equals(new QName("contact"))) {
        throw new XMLStreamException("Unexpected closing element");
      }
      while (reader.hasNext()) {
        int event = reader.next();
        if (event == XMLStreamConstants.END_DOCUMENT) {
          return contact;
        }
        if ((event == XMLStreamConstants.CHARACTERS && reader.isWhiteSpace())
            || event == XMLStreamConstants.COMMENT
            || event == XMLStreamConstants.PROCESSING_INSTRUCTION) {
          continue;
        }
        throw new XMLStreamException("Unexpected content after contact");
      }
      return contact;
    } finally {
      reader.close();
    }
  }
}
