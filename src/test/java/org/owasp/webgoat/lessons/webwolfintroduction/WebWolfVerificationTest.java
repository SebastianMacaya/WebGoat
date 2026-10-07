/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.web.client.RestTemplate;

class WebWolfVerificationTest {

  @Test
  void mailCodeMustBeReadFromTheUsersInboxAndCannotBeReused() {
    RestTemplate restTemplate = mock(RestTemplate.class);
    var codes = new VerificationCodes();
    var assignment = new MailAssignment(restTemplate, "http://webwolf/mail", codes);

    assignment.sendEmail("alice@webgoat.org", "alice");
    ArgumentCaptor<Email> sentMail = ArgumentCaptor.forClass(Email.class);
    verify(restTemplate)
        .postForEntity(eq("http://webwolf/mail"), sentMail.capture(), eq(Object.class));
    assertEquals("alice", sentMail.getValue().getRecipient());
    String code = sentMail.getValue().getContents().split("your unique code is: ")[1];

    assertFalse(assignment.completed("ecila", "alice").assignmentSolved());
    assertFalse(assignment.completed(code, "bob").assignmentSolved());
    assertTrue(assignment.completed(code, "alice").assignmentSolved());
    assertFalse(assignment.completed(code, "alice").assignmentSolved());
  }

  @Test
  void landingCodeMustComeFromThePageAndCannotBeReused() {
    var assignment = new LandingAssignment("http://webwolf//landing", new VerificationCodes());
    var page = assignment.openPasswordReset("alice");
    String code = (String) page.getModel().get("uniqueCode");

    assertEquals("http://webwolf/landing", page.getModel().get("webwolfLandingPageUrl"));
    assertEquals("alice", page.getModel().get("username"));
    assertFalse(assignment.click("ecila", "alice").assignmentSolved());
    assertFalse(assignment.click(code, "bob").assignmentSolved());
    assertTrue(assignment.click(code, "alice").assignmentSolved());
    assertFalse(assignment.click(code, "alice").assignmentSolved());
  }
}
