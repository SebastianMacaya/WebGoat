/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.UnsatisfiedServletRequestParameterException;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/***
 *
 * @author Angel Olle Blazquez
 *
 */

@AssignmentHints({"spoofcookie.hint1", "spoofcookie.hint2", "spoofcookie.hint3"})
@RestController
public class SpoofCookieAssignment implements AssignmentEndpoint {

  private static final String COOKIE_NAME = "spoof_auth";
  private static final Duration COOKIE_LIFETIME = Duration.ofMinutes(30);
  private static final String ATTACK_USERNAME = "tom";

  private static final Map<String, String> users =
      Map.of("webgoat", "webgoat", "admin", "admin", ATTACK_USERNAME, "apasswordfortom");
  private final SecureRandom random = new SecureRandom();
  private final Map<String, AuthenticatedCookie> authenticatedCookies = new ConcurrentHashMap<>();

  private record AuthenticatedCookie(String username, Instant expiresAt) {}

  @PostMapping(path = "/SpoofCookie/login")
  @ResponseBody
  @ExceptionHandler(UnsatisfiedServletRequestParameterException.class)
  public AttackResult login(
      @RequestParam String username,
      @RequestParam String password,
      @CookieValue(value = COOKIE_NAME, required = false) String cookieValue,
      HttpServletResponse response) {

    if (StringUtils.isEmpty(cookieValue)) {
      return credentialsLoginFlow(username, password, response);
    } else {
      return cookieLoginFlow(cookieValue);
    }
  }

  @GetMapping(path = "/SpoofCookie/cleanup")
  public void cleanup(
      @CookieValue(value = COOKIE_NAME, required = false) String cookieValue,
      HttpServletResponse response) {
    if (cookieValue != null) {
      authenticatedCookies.remove(cookieValue);
    }
    Cookie cookie = new Cookie(COOKIE_NAME, "");
    cookie.setPath("/WebGoat");
    cookie.setMaxAge(0);
    response.addCookie(cookie);
  }

  private AttackResult credentialsLoginFlow(
      String username, String password, HttpServletResponse response) {
    String lowerCasedUsername = username.toLowerCase();
    if (ATTACK_USERNAME.equals(lowerCasedUsername)
        && users.get(lowerCasedUsername).equals(password)) {
      return informationMessage(this).feedback("spoofcookie.cheating").build();
    }

    String authPassword = users.getOrDefault(lowerCasedUsername, "");
    if (!authPassword.isBlank() && authPassword.equals(password)) {
      Instant now = Instant.now();
      authenticatedCookies.entrySet().removeIf(entry -> !now.isBefore(entry.getValue().expiresAt()));
      byte[] token = new byte[32];
      random.nextBytes(token);
      String newCookieValue = Base64.getUrlEncoder().withoutPadding().encodeToString(token);
      authenticatedCookies.put(
          newCookieValue, new AuthenticatedCookie(lowerCasedUsername, now.plus(COOKIE_LIFETIME)));
      Cookie newCookie = new Cookie(COOKIE_NAME, newCookieValue);
      newCookie.setPath("/WebGoat");
      newCookie.setSecure(true);
      newCookie.setHttpOnly(true);
      newCookie.setMaxAge((int) COOKIE_LIFETIME.toSeconds());
      response.addCookie(newCookie);
      return informationMessage(this)
          .feedback("spoofcookie.login")
          .output("Authenticated as " + lowerCasedUsername)
          .build();
    }

    return informationMessage(this).feedback("spoofcookie.wrong-login").build();
  }

  private AttackResult cookieLoginFlow(String cookieValue) {
    AuthenticatedCookie authenticatedCookie = authenticatedCookies.get(cookieValue);
    if (authenticatedCookie != null && Instant.now().isBefore(authenticatedCookie.expiresAt())) {
      return failed(this)
          .feedback("spoofcookie.cookie-login")
          .output("Authenticated as " + authenticatedCookie.username())
          .build();
    }
    authenticatedCookies.remove(cookieValue);
    return failed(this).feedback("spoofcookie.wrong-cookie").build();
  }
}
