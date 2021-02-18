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

  @Value("${spring.config.exploits-dir}")
  private String EXPLOITS_DIR;

  @Value("${spring.config.joomla.config-dir}")
  private String CONFIG_DIR;

  @Value("${spring.config.joomla.endpoint-to-test}")
  private String ENDPOINT_TO_TEST;

  private static final Pattern PATTERN_JOOMLA =
      Pattern.compile("Joomla!(?:.*)\\s(Component|Plugin)(.*?)-(?:\\s)", Pattern.CASE_INSENSITIVE);

  private final Long MAX_TIME_TEST;

  @Autowired private SystemCve2Docker systemCve2Docker;

  public JoomlaService(@Value("${spring.config.joomla.max-time-test}") Integer MAX_TIME_TEST) {
    this.MAX_TIME_TEST = TimeUnit.MINUTES.toMillis(MAX_TIME_TEST);
  }

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

  public void copyContent(@NonNull File baseDir, @NonNull String product) throws IOException {

    FileUtils.copyDirectory(new File(CONFIG_DIR), baseDir);
    // Copy the env file and append the plugin or theme name
    var env = new File(baseDir, ".env");
    var contentEnv = readFileToString(env, StandardCharsets.UTF_8);

    contentEnv += "\nCOMPONENT_NAME=" + product;

    write(env, contentEnv, StandardCharsets.UTF_8);
  }
}
