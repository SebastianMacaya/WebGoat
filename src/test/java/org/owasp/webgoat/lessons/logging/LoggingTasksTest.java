/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;

class LoggingTasksTest {

  @Test
  void forgedLogLineCannotCompleteAssignmentOrReachOutput() {
    var result = new LogSpoofingTask().completed("guest\r\nadmin logged in", "irrelevant");

    assertFalse(result.assignmentSolved());
    assertEquals("Login failed", result.getOutput());
  }

  @Test
  void htmlInUsernameCannotReachOutput() {
    var result = new LogSpoofingTask().completed("<script>alert(1)</script>", "irrelevant");

    assertFalse(result.assignmentSolved());
    assertEquals("Login failed", result.getOutput());
  }

  @Test
  void passwordCannotBeGuessedFromThePublicLesson() {
    var result = new LogBleedingTask().completed("Admin", "admin");

    assertFalse(result.assignmentSolved());
  }
}
