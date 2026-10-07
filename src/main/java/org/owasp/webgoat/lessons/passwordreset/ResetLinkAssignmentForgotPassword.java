/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;

import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.Locale;
import java.util.UUID;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * Part of the password reset assignment. Used to send the e-mail.
 *
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class ResetLinkAssignmentForgotPassword implements AssignmentEndpoint {

  private final RestTemplate restTemplate;
  private final String webGoatURL;
  private final String webWolfHost;
  private final String webWolfPort;
  private final String webWolfURL;
  private final String webWolfMailURL;

  public ResetLinkAssignmentForgotPassword(
      RestTemplate restTemplate,
      @Value("${webgoat.url}") String webGoatURL,
      @Value("${webwolf.host}") String webWolfHost,
      @Value("${webwolf.port}") String webWolfPort,
      @Value("${webwolf.url}") String webWolfURL,
      @Value("${webwolf.mail.url}") String webWolfMailURL) {
    this.restTemplate = restTemplate;
    this.webGoatURL = webGoatURL.replaceAll("/+$", "");
    this.webWolfHost = webWolfHost;
    this.webWolfPort = webWolfPort;
    this.webWolfURL = webWolfURL.replaceAll("/+$", "");
    this.webWolfMailURL = webWolfMailURL;
  }

  @PostMapping("/PasswordReset/ForgotPassword/create-password-reset-link")
  @ResponseBody
  public AttackResult sendPasswordResetLink(
      @RequestParam String email, HttpServletRequest request, @CurrentUsername String username) {
    String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);
    String ownMailbox = username.toLowerCase(Locale.ROOT) + "@webgoat.org";
    if (!ownMailbox.equals(normalizedEmail)
        && !ResetLinkAssignment.TOM_EMAIL.equals(normalizedEmail)) {
      // Only lesson mailboxes can receive a token; the reply does not reveal whether one was sent.
      return informationMessage(this).feedback("email.send").feedbackArgs(email).build();
    }
    String resetLink = UUID.randomUUID().toString();
    ResetLinkAssignment.resetLinks.put(
        resetLink,
        new ResetLinkAssignment.ResetLink(
            normalizedEmail, Instant.now().plus(ResetLinkAssignment.RESET_LINK_LIFETIME)));
    try {
      sendMailToUser(normalizedEmail, resetLink);
    } catch (Exception e) {
      ResetLinkAssignment.resetLinks.remove(resetLink);
      return failed(this).output("E-mail can't be send. please try again.").build();
    }

    // The exercise's simulated click can still reach WebWolf, but it must never carry
    // the real reset token. This unrelated value is deliberately absent from resetLinks.
    String host = request.getHeader(HttpHeaders.HOST);
    if (ResetLinkAssignment.TOM_EMAIL.equals(normalizedEmail)
        && host != null
        && host.contains(webWolfHost)
        && host.contains(webWolfPort)) {
      fakeClickingDecoyLink(UUID.randomUUID().toString());
    }

    // Delivering a link is not proof that the requester controls the mailbox.
    return informationMessage(this).feedback("email.send").feedbackArgs(email).build();
  }

  private void sendMailToUser(String email, String resetLink) {
    int index = email.indexOf("@");
    String username = email.substring(0, index == -1 ? email.length() : index);
    PasswordResetEmail mail =
        PasswordResetEmail.builder()
            .title("Your password reset link")
            .contents(String.format(ResetLinkAssignment.TEMPLATE, webGoatURL, resetLink))
            .sender("password-reset@webgoat-cloud.net")
            .recipient(username)
            .build();
    this.restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
  }

  private void fakeClickingDecoyLink(String decoy) {
    try {
      restTemplate.exchange(
          String.format("%s/PasswordReset/reset/reset-password/%s", webWolfURL, decoy),
          HttpMethod.GET,
          new HttpEntity<>(new HttpHeaders()),
          Void.class);
    } catch (Exception ignored) {
      // This simulated click is only part of the lesson, never part of reset delivery.
    }
  }
}
