#ifndef QTFIREBASE_APPLE_NONCE_H
#define QTFIREBASE_APPLE_NONCE_H

#include <QString>

/// Nonce helpers for Sign in with Apple.
///
/// Apple receives SHA-256(rawNonce) in the authorization request and echoes it
/// back inside the identity token's `nonce` claim. Firebase receives the raw
/// nonce and verifies that its hash matches the claim, which binds the token to
/// this sign-in attempt and prevents replay.
namespace QtFirebaseAppleNonce {

/// Characters allowed in the raw nonce (URL-safe, matches Firebase's samples).
QString charset();

/// Cryptographically secure random nonce of @p length characters from charset().
/// Returns an empty string when @p length is not positive.
QString generateRawNonce(int length = 32);

/// Lowercase hex SHA-256 of the UTF-8 bytes of @p input.
QString sha256Hex(const QString &input);

} // namespace QtFirebaseAppleNonce

#endif // QTFIREBASE_APPLE_NONCE_H
