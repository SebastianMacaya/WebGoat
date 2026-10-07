/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.owasp.webgoat.lessons.webwolfintroduction.VerificationCodes.Purpose.LANDING;
import static org.owasp.webgoat.lessons.webwolfintroduction.VerificationCodes.Purpose.MAIL;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

class VerificationCodesTest {

  @Test
  void codesAreUnpredictableAndSingleUse() {
    var codes = new VerificationCodes();
    String first = codes.issue("alice", MAIL);
    String second = codes.issue("alice", MAIL);

    assertNotEquals("ecila", second);
    assertNotEquals(first, second);
    assertFalse(codes.consume("alice", MAIL, first));
    assertTrue(codes.consume("alice", MAIL, second));
    assertFalse(codes.consume("alice", MAIL, second));
  }

  @Test
  void codesBelongToOneUserAndOnePurpose() {
    var codes = new VerificationCodes();
    String code = codes.issue("alice", MAIL);

    assertFalse(codes.consume("bob", MAIL, code));
    assertFalse(codes.consume("alice", LANDING, code));
    assertTrue(codes.consume("alice", MAIL, code));
  }

  @Test
  void expiredCodesCannotBeUsed() {
    var clock = new MutableClock(Instant.parse("2026-10-07T12:00:00Z"));
    var codes = new VerificationCodes(clock);
    String code = codes.issue("alice", LANDING);

    clock.advance(VerificationCodes.LIFETIME);

    assertFalse(codes.consume("alice", LANDING, code));
  }

  private static class MutableClock extends Clock {
    private Instant current;

    private MutableClock(Instant current) {
      this.current = current;
    }

    void advance(java.time.Duration duration) {
      current = current.plus(duration);
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return Clock.fixed(current, zone);
    }

    @Override
    public Instant instant() {
      return current;
    }
  }
}
