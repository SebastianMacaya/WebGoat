/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.web.client.RestTemplate;

class SimpleMailAssignmentTest {

  @Test
  void resetCodeIsUnpredictableAndSingleUse() {
    RestTemplate mailClient = mock(RestTemplate.class);
    SimpleMailAssignment assignment = new SimpleMailAssignment(mailClient, "http://webwolf/mail");

    assertFalse(assignment.login("alice@webgoat.org", "ecila", "alice").isLessonCompleted());
    assignment.resetPassword("alice@webgoat.org", "alice");

    ArgumentCaptor<PasswordResetEmail> mail = ArgumentCaptor.forClass(PasswordResetEmail.class);
    verify(mailClient).postForEntity(eq("http://webwolf/mail"), mail.capture(), eq(Object.class));
    String contents = mail.getValue().getContents();
    String resetCode = contents.substring(contents.lastIndexOf(": ") + 2);

    assertFalse(assignment.login("alice@webgoat.org", "ecila", "alice").isLessonCompleted());
    assertTrue(assignment.login("alice@webgoat.org", resetCode, "alice").isLessonCompleted());
    assertFalse(assignment.login("alice@webgoat.org", resetCode, "alice").isLessonCompleted());
  }
}
