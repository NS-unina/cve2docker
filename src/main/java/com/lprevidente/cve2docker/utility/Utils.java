package com.lprevidente.cve2docker.utility;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
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

  public static String executeShellCmd(String cmd) throws IOException, InterruptedException {
    Runtime runtime = Runtime.getRuntime();
    Process pr = runtime.exec(cmd);
    pr.waitFor();
    BufferedReader reader = new BufferedReader(new InputStreamReader(pr.getInputStream()));
    return String.join("\n", reader.lines().toArray(String[]::new));
  }

  public static String executeProgram(File dir, String... cmd)
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
  public static String fromDockerRun2DockerCompose(String dockeRunCmd)
      throws IOException, InterruptedException {
    return executeShellCmd("composerize " + dockeRunCmd);
  }

  public static Date fromStringToDate(String date) throws ParseException {
    return YYYY_MM_DD.parse(date);
  }

  public static void extractZip(File input, File output) throws IOException {
    try (var zipFile = new ZipFile(input)) {
      var entries = zipFile.entries();
      while (entries.hasMoreElements()) {
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

  public static String formatString(@NonNull String in) {
    return in.toLowerCase().trim().replace(" ", "-").replace(".", "");
  }
}
