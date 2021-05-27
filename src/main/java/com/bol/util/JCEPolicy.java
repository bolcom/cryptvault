package com.bol.util;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * This is no longer required in java8, u162. see:
 * https://bugs.openjdk.java.net/browse/JDK-8170157
 */
@Deprecated
public final class JCEPolicy {
    private static final AtomicBoolean hackApplied = new AtomicBoolean(false);

    private JCEPolicy() {
        // ...
    }

    @Deprecated
    public static void allowUnlimitedStrength() {
        if (!hackApplied.compareAndSet(false, true)) return;

        try {
            if (!needApply()) return;

            Field field = Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted");
            field.setAccessible(true);

            Field modifiersField = Field.class.getDeclaredField("modifiers");
            modifiersField.setAccessible(true);
            modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);

            field.set(null, false);
        } catch (Throwable e) {
        }
    }

    public static boolean needApply() {
        String discard, major, minor, update, build;

        String[] javaVersionElements = System.getProperty("java.runtime.version").split("\\.|_|-b");

        discard = javaVersionElements[0];
        major = javaVersionElements[1];
        minor = javaVersionElements[2];
        update = javaVersionElements[3];
        build = javaVersionElements[4];

        return "1".equals(discard) && "8".equals(major);
    }
}
