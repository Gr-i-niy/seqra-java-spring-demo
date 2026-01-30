package org.example.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.TimeUnit;

public final class CommandExecutor {

    private static final int DEFAULT_TIMEOUT_SECONDS = 30;

    private CommandExecutor() {}

    public static class CommandResult {
        public final int exitCode;
        public final String output;
        public final String errorOutput;

        public CommandResult(int exitCode, String output, String errorOutput) {
            this.exitCode = exitCode;
            this.output = output;
            this.errorOutput = errorOutput;
        }

        public boolean isSuccess() {
            return exitCode == 0;
        }
    }

    // VULNERABLE: Shell execution with string concatenation
    public static CommandResult executeUnsafe(String command) throws IOException, InterruptedException {
        Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
        return readProcessOutput(process);
    }

    // SECURE: ProcessBuilder with argument list
    public static CommandResult executeSafe(List<String> command) throws IOException, InterruptedException {
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(true);
        Process process = processBuilder.start();
        return readProcessOutput(process);
    }

    private static CommandResult readProcessOutput(Process process) throws IOException, InterruptedException {
        StringBuilder output = new StringBuilder();
        StringBuilder errorOutput = new StringBuilder();

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                errorOutput.append(line).append("\n");
            }
        }

        boolean finished = process.waitFor(DEFAULT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        if (!finished) {
            process.destroy();
            throw new IOException("Command timeout exceeded");
        }

        return new CommandResult(process.exitValue(), output.toString(), errorOutput.toString());
    }
}
