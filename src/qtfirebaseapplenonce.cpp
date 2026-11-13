#include "qtfirebaseapplenonce.h"

#include <QCryptographicHash>
#include <QRandomGenerator>

namespace QtFirebaseAppleNonce {

QString charset()
{
    return QStringLiteral("0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz-._");
}

QString generateRawNonce(int length)
{
    if (length <= 0)
        return QString();

    const QString chars = charset();
    const quint32 charCount = static_cast<quint32>(chars.size());
    // Reject values that would bias the modulo so every character is equally likely.
    const quint32 limit = (0xFFFFFFFFu / charCount) * charCount;

    QString nonce;
    nonce.reserve(length);
    QRandomGenerator *rng = QRandomGenerator::system();
    while (nonce.size() < length) {
        const quint32 value = rng->generate();
        if (value >= limit)
            continue;
        nonce.append(chars.at(static_cast<int>(value % charCount)));
    }
    return nonce;
}

QString sha256Hex(const QString &input)
{
    return QString::fromLatin1(
        QCryptographicHash::hash(input.toUtf8(), QCryptographicHash::Sha256).toHex());
}

} // namespace QtFirebaseAppleNonce
