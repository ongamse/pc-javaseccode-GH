package org.joychou.security;

import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * ObjectInputStream that only resolves explicitly allowed classes (fail closed).
 * Use this instead of a deny list when deserializing data that came from a client.
 */
public class AllowlistObjectInputStream extends ObjectInputStream {

    private static final Set<String> ALLOWED = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "java.lang.String",
            "java.lang.Number",
            "java.lang.Integer",
            "java.lang.Long",
            "java.lang.Double",
            "java.lang.Boolean",
            "java.util.ArrayList",
            "java.util.HashMap",
            "org.joychou.security.AntObjectInputStream$MyObject"
    )));

    public AllowlistObjectInputStream(InputStream inputStream) throws IOException {
        super(inputStream);
    }

    @Override
    protected Class<?> resolveClass(final ObjectStreamClass desc)
            throws IOException, ClassNotFoundException {
        String className = desc.getName();
        // Array descriptors look like "[Ljava.lang.String;" or "[I"; check the element type.
        String elementName = className;
        while (elementName.startsWith("[")) {
            elementName = elementName.substring(1);
        }
        if (elementName.startsWith("L") && elementName.endsWith(";")) {
            elementName = elementName.substring(1, elementName.length() - 1);
        } else if (!className.equals(elementName)) {
            // Primitive array such as "[I"
            return super.resolveClass(desc);
        }
        if (!ALLOWED.contains(elementName)) {
            throw new InvalidClassException("Unauthorized deserialization attempt", className);
        }
        return super.resolveClass(desc);
    }
}
