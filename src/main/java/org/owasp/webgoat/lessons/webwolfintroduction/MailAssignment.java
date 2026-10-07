/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
import static org.owasp.webgoat.lessons.webwolfintroduction.VerificationCodes.Purpose.MAIL;

import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

/**
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class MailAssignment implements AssignmentEndpoint {

  private final String webWolfURL;
  private final RestTemplate restTemplate;
  private final VerificationCodes verificationCodes;

  public MailAssignment(
      RestTemplate restTemplate,
      @Value("${webwolf.mail.url}") String webWolfURL,
      VerificationCodes verificationCodes) {
    this.restTemplate = restTemplate;
    this.webWolfURL = webWolfURL;
    this.verificationCodes = verificationCodes;
  }

  @PostMapping("/WebWolf/mail/send")
  @ResponseBody
  public AttackResult sendEmail(
      @RequestParam String email, @CurrentUsername String webGoatUsername) {
    String username = email.substring(0, email.indexOf("@"));
    if (username.equalsIgnoreCase(webGoatUsername)) {
      String code = verificationCodes.issue(webGoatUsername, MAIL);
      Email mailEvent =
          Email.builder()
              .recipient(webGoatUsername)
              .title("Test messages from WebWolf")
              .contents(
                  "This is a test message from WebWolf, your unique code is: " + code)
              .sender("webgoat@owasp.org")
              .build();
      try {
        restTemplate.postForEntity(webWolfURL, mailEvent, Object.class);
      } catch (RestClientException e) {
        return informationMessage(this)
            .feedback("webwolf.email_failed")
            .output(e.getMessage())
            .build();
      }
      return informationMessage(this).feedback("webwolf.email_send").feedbackArgs(email).build();
    } else {
      return informationMessage(this)
          .feedback("webwolf.email_mismatch")
          .feedbackArgs(username)
          .build();
    }
  }

  @PostMapping("/WebWolf/mail")
  @ResponseBody
  public AttackResult completed(@RequestParam String uniqueCode, @CurrentUsername String username) {
    if (verificationCodes.consume(username, MAIL, uniqueCode)) {
      return success(this).build();
    } else {
      return failed(this).feedbackArgs("webwolf.code_incorrect").feedbackArgs(uniqueCode).build();
    }
  }
}
