package com.lprevidente.edb2docker.utility;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.yaml.snakeyaml.util.UriEncoder;

import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.zip.ZipFile;

@Slf4j
public class Utils {

  private static final SimpleDateFormat YYYY_MM_DD = new SimpleDateFormat("yyyy-MM-dd");

  private static final SimpleDateFormat YYYY_MM_DD_HH_MM_SS =
      new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");

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
   * Extract the <i>compress</i> file, with the the appropriate algorithm in the output directory
   * provided and after the extraction is completed the <b>zip file is deleted</b>.
   *
   * @param input the tar file
   * @param output the directory in which the zip should be extracted.
   * @throws IOException if an I/O error has occurred
   */
  public static void decompress(@NonNull File input, @NonNull File output) throws IOException {
    final var extension = FilenameUtils.getExtension(input.getName());
    switch (extension) {
      case "zip":
        unZip(input, output);
        break;
      case "tar":
        unTar(input, output);
        break;
      default:
        throw new IOException("Impossible to decompress: Unknown format: " + extension);
    }
  }

  /**
   * Extract the zip file in the output directory provided and after the extraction is completed the
   * <b>zip file is deleted</b>.
   *
   * @param input the zip file
   * @param output the directory in which the zip should be extracted.
   * @throws IOException if an I/O error has occurred
   */
  private static void unZip(@NonNull File input, @NonNull File output) throws IOException {
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

  /**
   * Extract the <b>tar</b> file in the output directory provided and after the extraction is
   * completed the <b>zip file is deleted</b>.
   *
   * @param input the tar file
   * @param output the directory in which the zip should be extracted.
   * @throws IOException if an I/O error has occurred
   */
  private static void unTar(@NonNull File input, @NonNull File output) throws IOException {
    try (var tar = new TarArchiveInputStream(new FileInputStream(input))) {
      TarArchiveEntry entry;
      while ((entry = tar.getNextTarEntry()) != null) {
        var entryDestination = new File(output, entry.getName());
        if (entry.isDirectory()) entryDestination.mkdirs();
        else {
          entryDestination.getParentFile().mkdirs();
          try (var out = new FileOutputStream(entryDestination)) {
            IOUtils.copy(tar, out);
          }
        }
      }
    }
    // Delete zip file after it has been extracted
    input.delete();
  }

  public static boolean isNotEmpty(@NonNull File input) {
    final var extension = FilenameUtils.getExtension(input.getName());
    switch (extension) {
      case "zip":
        return isZipNotEmpty(input);
      case "tar":
        return isTarNotEmpty(input);
      default:
        log.warn("Impossible to open the file. Extension unknown: {}", extension);
        return false;
    }
  }

  /**
   * Check if the zip file is empty or not. In case of error, the result is false.
   *
   * @param input the zip file
   * @return true is not empty, false otherwise
   */
  private static boolean isZipNotEmpty(@NonNull File input) {
    try {
      var zipFile = new ZipFile(input);
      var entries = zipFile.entries();
      return entries.hasMoreElements();
    } catch (IOException e) {
      return false;
    }
  }

  /**
   * Check if the tar file is empty or not. In case of error, the result is false.
   *
   * @param input the zip file
   * @return true is not empty, false otherwise
   */
  private static boolean isTarNotEmpty(@NonNull File input) {
    try {
      var tar = new TarArchiveInputStream(new FileInputStream(input));
      return tar.getNextTarEntry() != null;
    } catch (IOException e) {
      return false;
    }
  }

  /**
   * Copy a content from the link provided into the output provided. Also manage a possibile
   * redirection
   *
   * @param url the link
   * @param output where to store the file
   * @throws IOException if an I/O error has occurred
   */
  public static void copyURLToFile(@NonNull String url, @NonNull File output) throws IOException {
    try {
      var client = HttpClient.newHttpClient();
      var request =
          HttpRequest.newBuilder(new URI(UriEncoder.encode(url)))
              .method("HEAD", HttpRequest.BodyPublishers.noBody())
              .build();
      final var response = client.send(request, HttpResponse.BodyHandlers.discarding());

      if (response.statusCode() == 301) url = response.headers().map().get("Location").get(0);
      FileUtils.copyURLToFile(new URL(url), output);
    } catch (URISyntaxException | InterruptedException e) {
      throw new IOException("Error downloading vulnerable App: " + e.getMessage());
    }
  }

  public static String getLocationMoved(@NonNull String url) throws IOException {
    try {
      var client = HttpClient.newHttpClient();
      var request =
          HttpRequest.newBuilder(new URI(url))
              .method("HEAD", HttpRequest.BodyPublishers.noBody())
              .build();
      final var response = client.send(request, HttpResponse.BodyHandlers.discarding());

      if (response.statusCode() == 301 || response.statusCode() == 302)
        url = response.headers().map().get("Location").get(0);
      return url;
    } catch (URISyntaxException | InterruptedException e) {
      throw new IOException("Error during validation");
    }
  }

  /**
   * Format the input string replacing the space or : with -, removing the . (dots) and convert all
   * the characters in to lower case
   *
   * @param in input string
   * @return the string formatted
   */
  public static String formatString(@NonNull String in) {
    return in.toLowerCase().trim().replace(" ", "-").replace(".", "").replace(":", "-");
  }

  public static File createDir(@NonNull String path) throws IOException {
    final var dir = new File(path);
    // If already exist the directory delete it
    if (dir.exists()) FileUtils.deleteDirectory(dir);

    if (!dir.mkdirs()) throw new IOException("Impossible to create folder: " + dir.getPath());
    return dir;
  }
}
