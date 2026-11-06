package org.joychou.util;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Builds argv arrays for commands that may be influenced by user input.
 * Only allowlisted programs with simple option flags are accepted, and the
 * result is meant for ProcessBuilder / Runtime.exec(String[]) without a shell.
 */
public final class CommandUtil {

    private static final Set<String> ALLOWED_COMMANDS = Collections.unmodifiableSet(
            new HashSet<String>(Arrays.asList("whoami", "id", "date", "uname", "pwd", "hostname")));

    private static final Pattern FLAG_PATTERN = Pattern.compile("^-[a-zA-Z]{1,8}$");

    private CommandUtil() {
    }

    /**
     * @param cmd user supplied command line
     * @return argv (no shell) when the command and its flags are allowlisted, otherwise null
     */
    public static String[] toAllowedArgv(String cmd) {
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
            if (!FLAG_PATTERN.matcher(argv[i]).matches()) {
                return null;
            }
        }
        return argv;
    }
}
