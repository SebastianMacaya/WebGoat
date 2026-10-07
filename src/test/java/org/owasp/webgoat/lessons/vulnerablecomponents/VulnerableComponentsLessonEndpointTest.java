/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.vulnerablecomponents;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.assignments.AttackResult;

class VulnerableComponentsLessonEndpointTest {

  private final VulnerableComponentsLesson lesson = new VulnerableComponentsLesson();

  @Test
  void acceptsAPlainContact() {
    AttackResult result =
        lesson.completed(
            """
            <contact>
              <id>1</id>
              <firstName>Bruce</firstName>
              <lastName>Mayhew</lastName>
              <email>webgoat@owasp.org</email>
            </contact>
            """);

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("vulnerable-components.fromXML");
    assertThat(result.getFeedbackArgs()).hasSize(1);
    ContactImpl contact = (ContactImpl) result.getFeedbackArgs()[0];
    assertThat(contact.getId()).isEqualTo(1);
    assertThat(contact.getFirstName()).isEqualTo("Bruce");
    assertThat(contact.getLastName()).isEqualTo("Mayhew");
    assertThat(contact.getEmail()).isEqualTo("webgoat@owasp.org");
  }

  @Test
  void rejectsDynamicProxyContact() {
    AttackResult result =
        lesson.completed(
            """
            <contact class="dynamic-proxy">
              <interface>org.owasp.webgoat.lessons.vulnerablecomponents.Contact</interface>
              <handler class="java.beans.EventHandler">
                <target class="java.lang.ProcessBuilder">
                  <command><string>webgoat-never-run</string></command>
                </target>
                <action>start</action>
              </handler>
            </contact>
            """);

    assertRejected(result);
  }

  @Test
  void rejectsExternalEntity() {
    AttackResult result =
        lesson.completed(
            """
            <!DOCTYPE contact [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <contact><firstName>&xxe;</firstName></contact>
            """);

    assertRejected(result);
  }

  @Test
  void rejectsNestedObjectInContactField() {
    AttackResult result =
        lesson.completed("<contact><firstName><string>Bruce</string></firstName></contact>");

    assertRejected(result);
  }

  private void assertRejected(AttackResult result) {
    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("vulnerable-components.close");
  }
}
