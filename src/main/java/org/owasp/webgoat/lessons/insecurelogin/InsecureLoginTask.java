/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.insecurelogin;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
public class InsecureLoginTask implements AssignmentEndpoint {

  private final LessonSession lessonSession;

  public InsecureLoginTask(LessonSession lessonSession) {
    this.lessonSession = lessonSession;
  }

  @PostMapping("/InsecureLogin/task")
  @ResponseBody
  public AttackResult completed(
      @RequestParam(required = false) String username,
      @RequestParam(required = false) String password,
      @RequestBody(required = false) String body) {
    String currentUser = currentUsername();
    if (username == null
        && password == null
        && (body == null || body.isBlank())
        && currentUser.equals(lessonSession.getValue("insecure-login-user"))) {
      return success(this).build();
    }
    return failed(this).build();
  }

  @PostMapping("/InsecureLogin/login")
  @ResponseStatus(HttpStatus.ACCEPTED)
  public void login(@RequestBody(required = false) String body) {
    lessonSession.setValue("insecure-login-user", null);
    if (body != null && !body.isBlank()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Credentials are not accepted");
    }
    lessonSession.setValue("insecure-login-user", currentUsername());
  }

  private String currentUsername() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null
        || !authentication.isAuthenticated()
        || authentication instanceof AnonymousAuthenticationToken) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
    }
    return authentication.getName();
  }
}
