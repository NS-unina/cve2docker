package com.lprevidente.cve2docker.utility;

import javax.naming.ConfigurationException;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.concurrent.TimeUnit;

import static com.lprevidente.cve2docker.utility.Utils.executeProgram;

public class ConfigurationUtils {

  public static void setupConfiguration(
      File exploitDir, String endpoint, Long timeout, String... cmdSetup)
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
            res = executeProgram(exploitDir, cmdSetup);

            if (res.equals("ok")) setupCompleted = true;
            else throw new ConfigurationException("Impossible to setup docker: " + res);
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
        if (setupCompleted) executeProgram(exploitDir, "docker-compose", "stop");
        else executeProgram(exploitDir, "docker-compose", "rm", "-f");
      } catch (Exception ignored) {
      }
    }
  }
}
