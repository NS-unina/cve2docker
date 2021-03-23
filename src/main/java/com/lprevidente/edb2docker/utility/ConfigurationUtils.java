package com.lprevidente.edb2docker.utility;

import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import com.lprevidente.edb2docker.exception.ConfigurationException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;

import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import static com.lprevidente.edb2docker.utility.Utils.executeProgram;

@Slf4j
public class ConfigurationUtils {

  public static void setupConfiguration(
      @NonNull File exploitDir,
      @NonNull String endpoint,
      @NonNull Long timeout,
      boolean removeConfig,
      String... cmdSetup)
      throws ConfigurationException {
    boolean setupCompleted = false;
    try {
      var res = executeProgram(exploitDir, "sh", "start.sh");
      if (!res.equals("ok")) throw new ConfigurationException("Impossible to start docker: " + res);

      final long start = System.currentTimeMillis();
      final var client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
      final var request = HttpRequest.newBuilder(new URI(endpoint)).GET().build();

      // I try to setup wordpress in a maximum time
      setupCompleted = false;
      while ((System.currentTimeMillis() - start) <= timeout && !setupCompleted) {
        try {
          var response = client.send(request, HttpResponse.BodyHandlers.ofString());
          if (response.statusCode() == 200) {
            if (Objects.nonNull(cmdSetup)) res = executeProgram(exploitDir, cmdSetup);
            else res = "ok";

            if (res.equals("ok")) setupCompleted = true;
            else throw new ConfigurationException("Impossible to setup docker: " + res);
          } else {
            TimeUnit.SECONDS.sleep(2);
          }
        } catch (IOException ignore) {
          // Sleep for 2 seconds and than retry
          TimeUnit.SECONDS.sleep(2);
        }
      }

      // If time used to test exceeded MAX value means there might be some problem
      if (!setupCompleted)
        throw new ConfigurationException(
            "Exceeded the maximum time to test. Maybe te configuration is not correct");

    } catch (IOException | InterruptedException | URISyntaxException e) {
      e.printStackTrace();
      throw new ConfigurationException("Impossible to test configuration: " + e.getMessage());
    } finally {
      try {
        // If setup has been completed stock the container, otherwise remove it
        log.debug("Stopping container..");
        executeProgram(exploitDir, "docker-compose", "stop");
        if (!setupCompleted || removeConfig)
          executeProgram(exploitDir, "docker-compose", "rm", "-v", "-f");
      } catch (Exception ignored) {
      }
    }
  }

  public static YAMLFactory getYAMLFactoryDockerCompose() {
    return new YAMLFactory()
        .configure(YAMLGenerator.Feature.INDENT_ARRAYS_WITH_INDICATOR, true)
        .configure(YAMLGenerator.Feature.ALWAYS_QUOTE_NUMBERS_AS_STRINGS, true)
        .configure(YAMLGenerator.Feature.MINIMIZE_QUOTES, true)
        .configure(YAMLGenerator.Feature.INDENT_ARRAYS, true)
        .configure(YAMLGenerator.Feature.WRITE_DOC_START_MARKER, false);
  }

  public static void copyFiles(@NonNull String directory, @NonNull File destDir, String[] files)
      throws IOException {

    for (var filename : files) {
      // Creating the file
      var file = new File(destDir, filename);
      file.getParentFile().mkdirs();
      IOUtils.copy(
          getBufferedReaderResource(directory+"/"+filename),
          new FileOutputStream(file.getPath()),
          StandardCharsets.UTF_8);
    }
  }

  public static BufferedReader getBufferedReaderResource(@NonNull String path) throws IOException {
    var in = ConfigurationUtils.class.getClassLoader().getResourceAsStream(path);

    if (Objects.isNull(in)) throw new IOException("File " + path + " not found in resource folder");

    return new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
  }
}
