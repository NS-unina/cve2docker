package com.lprevidente.cve2docker.utility;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import java.io.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipFile;

@Slf4j
public class Utils {

  // RegEx for Cmd Docker Run
  private static final Pattern PATTERN_DOCKER_RUN =
      Pattern.compile("docker run [^`]*", Pattern.CASE_INSENSITIVE);

  private static final SimpleDateFormat YYYY_MM_DD = new SimpleDateFormat("yyyy-MM-dd");

  private static final SimpleDateFormat YYYY_MM_DD_HH_MM_SS =
      new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");

  /**
   * Find inside the text the 'docker run' cmd
   *
   * @param text where to search
   * @return an array with all accurrency of the pattern. In case of no cmd found, the array is
   *     empty
   */
  public static String[] getDockerRunCmdLine(@NonNull String text) {
    Matcher matcher = PATTERN_DOCKER_RUN.matcher(text);
    return matcher.results().map(MatchResult::group).toArray(String[]::new);
  }

  /**
   * Utility to execute the a shell command.
   *
   * @param cmd The entire command to execute
   * @return The result of execution
   * @throws IOException If an I/O error occurs
   * @throws InterruptedException If the current thread is interrupted by another thread while it is
   *     waiting, then the wait is ended and an InterruptedException is thrown
   */
  public static String executeShellCmd(@NonNull String cmd)
      throws IOException, InterruptedException {
    Runtime runtime = Runtime.getRuntime();
    Process pr = runtime.exec(cmd);
    pr.waitFor();
    BufferedReader reader = new BufferedReader(new InputStreamReader(pr.getInputStream()));
    return String.join("\n", reader.lines().toArray(String[]::new));
  }

  /**
   * Utility to execute the a shell command in a folder
   *
   * @param dir The folder in which the command should be execute
   * @param cmd A string array containing the program and its arguments
   * @return The result of execution
   * @throws IOException If an I/O error occurs
   * @throws InterruptedException If the current thread is interrupted by another thread while it is
   *     waiting, then the wait is ended and an InterruptedException is thrown
   */
  public static String executeProgram(@NonNull File dir, @NonNull String... cmd)
      throws IOException, InterruptedException {
    ProcessBuilder builder = new ProcessBuilder(cmd);
    builder.directory(dir.getCanonicalFile());
    builder.redirectErrorStream(true);
    Process process = builder.start();
    process.waitFor();
    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
    return String.join("\n", reader.lines().toArray(String[]::new));
  }

  /**
   * Execute the library composerize to transform a cmd of type 'docker run' to a docker-compose
   *
   * @param dockeRunCmd the cmd to be transform
   * @return a string corrispondent to docker compose
   * @throws IOException in case of error
   * @throws InterruptedException in case of error
   */
  public static String fromDockerRun2DockerCompose(@NonNull String dockeRunCmd)
      throws IOException, InterruptedException {
    return executeShellCmd("composerize " + dockeRunCmd);
  }

  /**
   * Convert a String to date
   *
   * @param date must by in the format yy-MM-dd
   * @return the object date
   * @throws ParseException if the beginning of the specified string cannot be parsed.
   */
  public static Date fromStringToDate(@NonNull String date) throws ParseException {
    return YYYY_MM_DD.parse(date);
  }

  /**
   * Convert a Date to String
   *
   * @param date must by in the format yy-MM-dd
   * @return the string in the format yyyy-MM-dd'T'HH:mm:ss
   */
  public static String fromDateToString(@NonNull Date date) {
    return YYYY_MM_DD_HH_MM_SS.format(date);
  }

  /**
   * Extract the zip file in the output directory provided and after the extraction is completed the
   * <b>zip file is deleted</b>.
   *
   * @param input the zip file
   * @param output the directory in which the zip should be extracted.
   * @throws IOException if an I/O error has occurred
   */
  public static void extractZip(@NonNull File input, @NonNull File output) throws IOException {
    try (var zipFile = new ZipFile(input)) {
      var entries = zipFile.entries();
      while (entries.hasMoreElements()) {
        // TODO: create zip folder
        var entry = entries.nextElement();
        var entryDestination = new File(output, entry.getName());
        if (entry.isDirectory()) {
          entryDestination.mkdirs();
        } else {
          entryDestination.getParentFile().mkdirs();
          try (var in = zipFile.getInputStream(entry);
              var out = new FileOutputStream(entryDestination)) {
            IOUtils.copy(in, out);
          }
        }
      }
      // Delete zip file after it has been extracted
      input.delete();
    }
  }

  /**
   * Format the input string replacing the space with -, removing the . (dots) and convert all the
   * characters in to lower case
   *
   * @param in input string
   * @return the string formatted
   */
  public static String formatString(@NonNull String in) {
    return in.toLowerCase().trim().replace(" ", "-").replace(".", "");
  }

  public static File createDir(@NonNull String path) throws IOException {
    final var dir = new File(path);
    // If already exist the directory delete it
    if (dir.exists()) FileUtils.deleteDirectory(dir);

    if (!dir.mkdirs())
      throw new IOException("Impossible to create folder: " + dir.getPath());
    return dir;
  }
}
