package com.lprevidente.cve2docker.service;

import com.lprevidente.cve2docker.TestBase;
import com.lprevidente.cve2docker.exception.ExploitUnsupported;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

public class WordpressServiceTest extends TestBase {
  @Value("${spring.config.exploits-dir}")
  private String EXPLOITS_DIR;

  @Autowired private SystemCve2Docker service;

  @Test
  public void testGenericWordpress() throws IOException {
    var edbID = "49539";
    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    FileUtils.deleteDirectory(dir);

    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID));
  }

  /**
   * Exploit Wordpress <i>Plugin</i> <b>Form Maker</b> with Software Link related to Wordpress site
   */
  @Test
  public void genConfigurationFromExploitWordpressPluginFormMaker() throws IOException {
    var edbID = "44559";
    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    FileUtils.deleteDirectory(dir);

    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID));

    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("PLUGIN_NAME=form-maker"));
  }

  /**
   * Exploit Wordpress <i>Plugin</i> <b>WP Paginate</b> with Software Link related to Wordpress site
   */
  @Test
  public void genConfigurationFromExploitWordpressPluginWPPaginate() throws IOException {
    var edbID = "49355";
    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    FileUtils.deleteDirectory(dir);

    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID));

    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("PLUGIN_NAME=wp-paginate"));
  }

  /**
   * Exploit Wordpress <i>Plugin</i> <b>ColorBox</b> with Software Link related to Wordpress site
   */
  @Test
  public void genConfigurationFromExploitWordpressPluginColorbox() throws IOException {
    var edbID = "48919";

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    FileUtils.deleteDirectory(dir);

    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID));

    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("PLUGIN_NAME=wp-colorbox"));
  }

  /**
   * Exploit Wordpress <i>Plugin</i> <b>Easy Contact Form</b> with no Software Link related to
   * Wordpress site and present in SVN but no tag related. Expected Exploit Unsupported Exception
   */
  @Test
  public void genConfigurationFromExploitWordpressEasyContactForm() throws IOException {
    var edbID = "49427";
    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    FileUtils.deleteDirectory(dir);

    assertThrows(ExploitUnsupported.class, () -> service.genConfigurationFromExploit(edbID));
  }

  /**
   * Exploit Wordpress <i>Theme</i> <b>Fruitful</b> with Software Link related to Wordpress site.
   */
  @Test
  public void genConfigurationFromExploitWordpressTheme() throws IOException {
    var edbID = "48083";
    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    FileUtils.deleteDirectory(dir);

    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID));

    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("THEME_NAME=fruitful"));
  }

  /**
   * Exploit Wordpress <i>Theme</i> <b>Fruitful</b> with no Software Link related to Wordpress site
   * but with vuln App.
   */
  @Test
  public void genConfigurationFromExploitWordpressThemeNoSVN() throws IOException {
    var edbID = "39552";
    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    FileUtils.deleteDirectory(dir);

    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID));

    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("THEME_NAME=beauty-&-clean/beauty-premium"));
  }

  /** Exploit Wordpress <i>Core</i> with Software Link, but this should not be used. */
  @Test
  public void genConfigurationFromExploitWordpressCore() throws IOException {
    final var edbID = "47557";
    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    FileUtils.deleteDirectory(dir);

    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID));

    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("WORDPRESS_VERSION=5.2.4"));
  }

  /** Exploit Wordpress <i>Core</i> with 2 versions 4.7.0/4.7.1. */
  @Test
  public void genConfigurationFromExploitWordpressCore2Version() throws IOException {
    final var edbID = "41224";
    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    FileUtils.deleteDirectory(dir);

    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID));

    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("WORDPRESS_VERSION=4.7.1"));
  }
}
