/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.assignments.AttackResult;

class QuestionsAssignmentTest {

  @Test
  void publicAnswersCannotResetPasswordsOrEnumerateUsers() {
    QuestionsAssignment assignment = new QuestionsAssignment();
    AttackResult knownUser =
        assignment.passwordReset(Map.of("username", "tom", "securityQuestion", "purple"));
    AttackResult unknownUser =
        assignment.passwordReset(Map.of("username", "missing", "securityQuestion", "purple"));

    assertFalse(knownUser.isLessonCompleted());
    assertFalse(unknownUser.isLessonCompleted());
    assertEquals(knownUser.getFeedback(), unknownUser.getFeedback());
  }
}
