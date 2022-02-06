#ifndef ANDROIDEXTRAS_H
#define ANDROIDEXTRAS_H

#include <qglobal.h>

#if defined(Q_OS_ANDROID)
#include <QCoreApplication>
#include <QJniObject>

using QtJniObject = QJniObject;

inline QtJniObject qtAndroidContext()
{
    return QJniObject(QCoreApplication::instance()
->nativeInterface<QNativeInterface::QAndroidApplication>()
                      ->context());
}

inline int qtAndroidSdkVersion()
{
    return QCoreApplication::instance()
->nativeInterface<QNativeInterface::QAndroidApplication>()
            ->sdkVersion();
}
#endif

#endif // ANDROIDEXTRAS_H
