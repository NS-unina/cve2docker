package com.lprevidente.cve2docker.service;

import com.lprevidente.cve2docker.entity.pojo.ExploitDB;
import com.lprevidente.cve2docker.exception.ConfigurationException;
import com.lprevidente.cve2docker.exception.ExploitUnsupported;
import com.lprevidente.cve2docker.utility.ConfigurationUtils;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import static org.apache.commons.io.FileUtils.readFileToString;
import static org.apache.commons.io.FileUtils.write;

@Slf4j
@Service
public class JoomlaService {

  @Autowired private SystemCve2Docker systemCve2Docker;

  @Value("${spring.config.exploits-dir}")
  private String EXPLOITS_DIR;

  @Value("${spring.config.joomla.config-dir}")
  private String CONFIG_DIR;

  @Value("${spring.config.joomla.endpoint-to-test}")
  private String ENDPOINT_TO_TEST;

  private static final Pattern PATTERN_JOOMLA =
      Pattern.compile("Joomla!(?:.*)\\s(Component|Plugin)(.*?)-(?:\\s)", Pattern.CASE_INSENSITIVE);

  private final Long MAX_TIME_TEST;

  public JoomlaService(@Value("${spring.config.joomla.max-time-test}") Integer MAX_TIME_TEST) {
    this.MAX_TIME_TEST = TimeUnit.MINUTES.toMillis(MAX_TIME_TEST);
  }

  /**
   * Method to generate configuration for the exploit related to <b>Joomla</b>. The configuration
   * consist in docker-compose, env file e other files depending on the exploit type.
   *
   * <p>The configuration is saved in ./content/generated/{edbID} folder.
   *
   * @param exploit not null
   * @param removeConfig if true the configuration will be removed after it has been setup.
   * @throws ExploitUnsupported throws when there is no possibility to generate the configuration.
   * @throws IOException throw when there is a problem with I/O operation
   * @throws ConfigurationException throws when there is a problem during the setup or test of the
   *     configuration.
   */
  public void genConfiguration(@NonNull ExploitDB exploit, boolean removeConfig)
      throws ExploitUnsupported, IOException, ConfigurationException {
    log.info("Generating configuration for Joomla Exploit");
    final var matcherJoomla = PATTERN_JOOMLA.matcher(exploit.getTitle());

    if (!matcherJoomla.find())
      throw new ExploitUnsupported("Pattern title unknown: " + exploit.getTitle());

    if (exploit.getFilenameVulnApp() != null) {
      // Creating the directoty
      final var exploitDir = new File(EXPLOITS_DIR + "/" + exploit.getId());

      if (!exploitDir.exists() && !exploitDir.mkdirs())
        throw new IOException("Impossible to create folder: " + exploitDir.getPath());

      log.info("Exploit has Vulnerable App. Downloading it");
      final var zipFile = new File(exploitDir, "/component/" + exploit.getFilenameVulnApp());
      systemCve2Docker.downloadVulnApp(exploit.getFilenameVulnApp(), zipFile);

      // Copy All necessary files
      copyContent(exploitDir, exploit.getFilenameVulnApp());
      log.info("Configuration created. Trying to configure it..");

      // Setup
      ConfigurationUtils.setupConfiguration(
          exploitDir,
          ENDPOINT_TO_TEST,
          MAX_TIME_TEST,
          removeConfig,
          "sh",
          "setup.sh",
          exploit.getFilenameVulnApp());

      log.info("Container configured correctly!");
    } else {
      // log.warn("No Vulnerable App available. Cannot complete!");
      throw new ExploitUnsupported("No Vulnerable App available. Cannot complete!");
    }
  }

  /**
   * Copy the content from the configuration directory into the directory provided. Also modifies
   * the env file inserting the name of Joomla component.
   *
   * @param baseDir the directory in which the files should be copied. component the name of Joomla
   *     component.
   * @param component the name of joomla component
   * @throws IOException if the file provided is not a directory or an error during the copy
   *     process.
   */
  private void copyContent(@NonNull File baseDir, @NonNull String component) throws IOException {
    if (!baseDir.isDirectory()) throw new IOException("The baseDir provided is not a directory");

    FileUtils.copyDirectory(new File(CONFIG_DIR), baseDir);
    // Copy the env file and append the component name
    var env = new File(baseDir, ".env");
    var contentEnv = readFileToString(env, StandardCharsets.UTF_8);

    contentEnv += "\nCOMPONENT_NAME=" + component;

    write(env, contentEnv, StandardCharsets.UTF_8);
  }
}
