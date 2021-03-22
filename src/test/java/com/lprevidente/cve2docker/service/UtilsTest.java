package com.lprevidente.cve2docker.service;

import com.lprevidente.cve2docker.TestBase;
import com.lprevidente.cve2docker.utility.ConfigurationUtils;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

public class UtilsTest extends TestBase {

  @Value("${spring.config.exploits-dir}")
  private String EXPLOITS_DIR;

  @Value("${spring.config.joomla.config-dir}")
  private String JOOMLA_CONFIG_DIR;

  @Value("${spring.config.wordpress.config-dir}")
  private String WORDPRESS_CONFIG_DIR;

  private final String[] joomlaFilenames =
      new String[] {
        "docker-compose.yml",
        "start.sh",
        "setup.sh",
        ".env",
        "config/mysql/init.sql",
        "config/joomla/configuration.php",
        "config/joomla/install-joomla-extension.php"
      };

  private static final String[] wordpressFilenames =
      new String[] {"docker-compose.yml", "start.sh", "setup.sh", ".env"};

  @Test
  public void testJoomlaCopy() {
    assertDoesNotThrow(
        () -> {
          var dir = new File("./exploits/test/joomla");
          ConfigurationUtils.copyFiles(JOOMLA_CONFIG_DIR, dir, joomlaFilenames);
          FileUtils.deleteDirectory(dir);
        });
  }

  @Test
  public void testWordpressCopy() {
    assertDoesNotThrow(
        () -> {
          var dir = new File("./exploits/test/wordpress");
          ConfigurationUtils.copyFiles(WORDPRESS_CONFIG_DIR, dir, wordpressFilenames);
          FileUtils.deleteDirectory(dir);
        });
  }
}
