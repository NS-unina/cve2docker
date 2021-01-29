package com.lprevidente.cve2docker.utility;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

@Slf4j
public class Utils {

  // RegEx for Cmd Docker Run
  private static final Pattern PATTERN_DOCKER_RUN =
      Pattern.compile("docker run [^`]*", Pattern.CASE_INSENSITIVE);

  // Path of Resources folder = where to store files
  private static final String RESOURCE_FOLDER = "./resource";

  private static SimpleDateFormat YYYY_MM_DD = new SimpleDateFormat("yyyy-MM-dd");

  public static <T> T readObjFromResourceFile(String filename, Class<T> tClass) {
    try {
      File file = new File(Utils.class.getResource(filename).getFile());
      if (file.exists()) {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(file, tClass);
      }
    } catch (IOException e) {
      log.error("An exception occurred: {}", e.getMessage());
    }
    return null;
  }

  public <T> T readObjFromResourceFile(String filename, TypeReference<T> valueTypeRef) {
    try {
      File file = new File(RESOURCE_FOLDER + "/" + filename);
      if (file.exists()) {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(file, valueTypeRef);
      }
    } catch (IOException e) {
      log.error("An exception occurred: {}", e.getMessage());
    }
    return null;
  }

  public static <T> void writeObjInResourceFile(String filename, Object object) {
    try {
      String path = RESOURCE_FOLDER + "/" + filename;
      createDirIfNotExist(path);
      File file = new File(path);
      ObjectMapper objectMapper = new ObjectMapper();
      objectMapper.writeValue(file, object);
    } catch (IOException e) {
      log.error("An exception occurred: {}", e.getMessage());
    }
  }

  public static void writeStrInResourceFile(String text, String filename) {
    try {
      String path = RESOURCE_FOLDER + "/" + filename;
      createDirIfNotExist(path);
      File file = new File(path);
      OutputStream outputStream = new FileOutputStream(file);
      IOUtils.write(text, outputStream, StandardCharsets.UTF_8);
    } catch (Exception e) {
      log.error(
          "An exception occurred during write file {} - Error: {}",
          filename,
          e.getLocalizedMessage());
      e.printStackTrace();
    }
  }

  private static void createDirIfNotExist(String path) throws IOException {
    if (path.contains("/")) {
      File file = new File(path.substring(0, path.lastIndexOf("/") + 1));
      if (!file.exists()) Files.createDirectories(file.toPath());
    }
  }

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
      var firstDirectory = true;
      var nameFirstDir = "";
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
