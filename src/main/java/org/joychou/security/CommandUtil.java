package org.joychou.security;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;


/**
 * Helper for running user supplied command lines without a shell.
 * The executable must be in a fixed allowlist and every argument must
 * pass {@link SecurityUtil#cmdFilter(String)}.
 */
public final class CommandUtil {

    private static final Set<String> ALLOWED_COMMANDS = Collections.unmodifiableSet(
            new HashSet<String>(Arrays.asList("whoami", "id", "uname", "pwd", "ls")));

    private CommandUtil() {
    }

    /**
     * Split a command line into argv and validate it.
     *
     * @param cmd command line, whitespace separated
     * @return argv array that can be passed to ProcessBuilder (no shell), or null if the
     *         command is not allowed
     */
    public static String[] parseAllowedCommand(String cmd) {
        if (cmd == null) {
            return null;
        }
        String trimmed = cmd.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        String[] argv = trimmed.split("\\s+");
        if (!ALLOWED_COMMANDS.contains(argv[0])) {
            return null;
        }
        for (int i = 1; i < argv.length; i++) {
            if (SecurityUtil.cmdFilter(argv[i]) == null) {
                return null;
            }
        }
        return argv;
    }
}
