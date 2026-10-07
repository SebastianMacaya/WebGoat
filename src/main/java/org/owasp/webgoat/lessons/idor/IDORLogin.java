/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"idor.hints.idor_login"})
public class IDORLogin implements AssignmentEndpoint {
  private final LessonSession lessonSession;

  public IDORLogin(LessonSession lessonSession) {
    this.lessonSession = lessonSession;
  }

  @PostMapping("/IDOR/login")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    String webGoatUsername = IDORAccessPolicy.requireWebGoatUsername();
    lessonSession.setValue("idor-webgoat-user", null);
    lessonSession.setValue("idor-authenticated-as", null);
    lessonSession.setValue("idor-authenticated-user-id", null);
    lessonSession.setValue("idor-profile-2342384", null);
    lessonSession.setValue("idor-profile-2342388", null);

    Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    if (principal instanceof WebGoatUser account
        && webGoatUsername.equals(username)
        && account.getPassword().equals(password)) {
      lessonSession.setValue("idor-webgoat-user", webGoatUsername);
      lessonSession.setValue("idor-authenticated-as", "tom");
      lessonSession.setValue("idor-authenticated-user-id", IDORAccessPolicy.TOM_ID);
      return success(this).feedback("idor.login.success").feedbackArgs(username).build();
    }
    return failed(this).feedback("idor.login.failure").build();
  }
}
