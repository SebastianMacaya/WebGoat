/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

@Component
public class VerificationCodes {

  enum Purpose {
    MAIL,
    LANDING
  }

  static final Duration LIFETIME = Duration.ofMinutes(10);

  private final SecureRandom random = new SecureRandom();
  private final Map<Key, PendingCode> pendingCodes = new ConcurrentHashMap<>();
  private final Clock clock;

  public VerificationCodes() {
    this(Clock.systemUTC());
  }

  VerificationCodes(Clock clock) {
    this.clock = clock;
  }

  String issue(String username, Purpose purpose) {
    byte[] bytes = new byte[32];
    random.nextBytes(bytes);
    String code = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    pendingCodes.put(
        new Key(username, purpose), new PendingCode(code, clock.instant().plus(LIFETIME)));
    return code;
  }

  boolean consume(String username, Purpose purpose, String candidate) {
    if (candidate == null) {
      return false;
    }

    Key key = new Key(username, purpose);
    PendingCode pendingCode = pendingCodes.get(key);
    if (pendingCode == null) {
      return false;
    }
    if (!clock.instant().isBefore(pendingCode.expiresAt())) {
      pendingCodes.remove(key, pendingCode);
      return false;
    }

    boolean matches =
        MessageDigest.isEqual(
            candidate.getBytes(StandardCharsets.UTF_8),
            pendingCode.value().getBytes(StandardCharsets.UTF_8));
    return matches && pendingCodes.remove(key, pendingCode);
  }

  private record Key(String username, Purpose purpose) {}

  private record PendingCode(String value, Instant expiresAt) {}
}
