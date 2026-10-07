/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.logging;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LogSpoofingTask implements AssignmentEndpoint {

  @PostMapping("/LogSpoofing/log-spoofing")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    // A username is untrusted data. Do not let it create a forged log line or HTML output.
    return failed(this).output("Login failed").build();
  }
}
