package com.lprevidente.cve2docker.service;

import com.lprevidente.cve2docker.entity.pojo.ExploitDB;
import com.lprevidente.cve2docker.exception.ExploitUnsupported;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.naming.ConfigurationException;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import static com.lprevidente.cve2docker.utility.Utils.executeProgram;
import static org.apache.commons.io.FileUtils.readFileToString;
import static org.apache.commons.io.FileUtils.write;

@Slf4j
@Service
public class JoomlaService {

  @Value("${spring.config.exploits-dir}")
  private String EXPLOITS_DIR;

  @Value("${spring.config.joomla.base-dir}")
  private String JOOMLA_DIR;

  @Value("${spring.config.joomla.endpoint-to-test}")
  private String ENDPOINT_TO_TEST;

  private static final Pattern PATTERN_JOOMLA =
      Pattern.compile("Joomla!(?:.*)\\s(Component|Plugin)(.*?)-(?:\\s)", Pattern.CASE_INSENSITIVE);

  private final Long MAX_TIME_TEST;

  @Autowired private SystemCve2Docker systemCve2Docker;

  public JoomlaService(@Value("${spring.config.joomla.max-time-test}") Integer MAX_TIME_TEST) {
    this.MAX_TIME_TEST = TimeUnit.MINUTES.toMillis(MAX_TIME_TEST);
  }

  public void genConfiguration(@NonNull ExploitDB exploit)
      throws ExploitUnsupported, IOException, ConfigurationException {
    log.info("Generating configuration for Joomla Exploit");
    final var matcherJoomla = PATTERN_JOOMLA.matcher(exploit.getTitle());

    if (!matcherJoomla.find())
      throw new ExploitUnsupported("Pattern title unknown: " + exploit.getTitle());

    // Extract from title the Type and Target (aka Product)s
    final var exploitDir = new File(EXPLOITS_DIR + "/" + exploit.getId());

    if (!exploitDir.exists() && !exploitDir.mkdirs())
      throw new IOException("Impossible to create folder: " + exploitDir.getPath());

    if (exploit.getFilenameVulnApp() != null) {
      log.info("Exploit has Vuln App. Downloading it");
      final var zipFile = new File(exploitDir, "/component/" + exploit.getFilenameVulnApp());
      systemCve2Docker.downloadVulnApp(exploit.getFilenameVulnApp(), zipFile);

      // Copy All necessary files
      copyContent(exploitDir, exploit.getFilenameVulnApp());
      log.info("Configuration created. Trying to configure it..");

      // Setup
      setupConfiguration(exploitDir, exploit.getFilenameVulnApp());
      log.info("Container configured correctly!");
    } else throw new ExploitUnsupported("No Vulnerable App available. Cannot complete!");
  }

  public void copyContent(@NonNull File baseDir, @NonNull String product) throws IOException {

    FileUtils.copyDirectory(new File(JOOMLA_DIR), baseDir);
    // Copy the env file and append the plugin or theme name
    var env = new File(baseDir, ".env");
    var contentEnv = readFileToString(env, StandardCharsets.UTF_8);

    contentEnv += "\nCOMPONENT_NAME=" + product;

    write(env, contentEnv, StandardCharsets.UTF_8);
  }

  public void setupConfiguration(File exploitDir, String product) throws ConfigurationException {
    boolean setupCompleted = false;
    try {
      var res = executeProgram(exploitDir, "sh", "start.sh");
      if (!res.equals("ok")) throw new ConfigurationException("Impossible to start docker: " + res);

      final long start = System.currentTimeMillis();
      final var client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
      final var request = HttpRequest.newBuilder(new URI(ENDPOINT_TO_TEST)).GET().build();

      // I try to setup Joomla for a maximum time
      setupCompleted = false;
      while ((System.currentTimeMillis() - start) <= MAX_TIME_TEST && !setupCompleted) {
        try {
          var response = client.send(request, HttpResponse.BodyHandlers.ofString());
          if (response.statusCode() == 200) {
            res = executeProgram(exploitDir, "sh", "setup.sh", product);

            if (res.equals("ok")) setupCompleted = true;
            else throw new ConfigurationException("Impossible to start docker: " + res);
          }
        } catch (IOException ignore) {
          // Sleep for 2 seconds and than retry
          TimeUnit.SECONDS.sleep(2);
        }
      }

      // If time used to test exceeded MAX value means there might be some problem
      if (!setupCompleted)
        throw new ConfigurationException(
            "Exceeded the maximum time to test. Maybe something is wrong with setup.");
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
