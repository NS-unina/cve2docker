package com.lprevidente.cve2docker.service;

import com.lprevidente.cve2docker.TestBase;
import com.lprevidente.cve2docker.exception.NoVulnerableAppException;
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
    final var edbID = 49539L;
    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    FileUtils.deleteDirectory(dir);

    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID, false));
    FileUtils.deleteDirectory(dir);
  }

  /**
   * Exploit Wordpress <i>Plugin</i> <b>Form Maker</b> with Software Link related to Wordpress site
   */
  @Test
  public void genConfigurationPluginFormMaker() throws IOException {
    final var edbID = 44559L;
    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("PLUGIN_NAME=form-maker"));
    FileUtils.deleteDirectory(dir);
  }

  /**
   * Exploit Wordpress <i>Plugin</i> <b>WP Paginate</b> with Software Link related to Wordpress site
   */
  @Test
  public void genConfigurationPluginWPPaginate() throws IOException {
    final var edbID = 49355L;
    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("PLUGIN_NAME=wp-paginate"));
    FileUtils.deleteDirectory(dir);
  }

  /**
   * Exploit Wordpress <i>Plugin</i> <b>ColorBox</b> with Software Link related to Wordpress site
   */
  @Test
  public void genConfigurationPluginColorbox() throws IOException {
    final var edbID = 48919L;
    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("PLUGIN_NAME=wp-colorbox"));
    FileUtils.deleteDirectory(dir);
  }

  /**
   * Exploit Wordpress <i>Plugin</i> <b>Easy Contact Form</b> with no Software Link related to
   * Wordpress site and present in SVN but no tag related. Expected Exploit Unsupported Exception
   */
  @Test
  public void genConfigurationPluginEasyContactForm() {
    final var edbID = 49427L;
    assertThrows(
        NoVulnerableAppException.class, () -> service.genConfigurationFromExploit(edbID, false));
  }

  /**
   * Exploit Wordpress <i>Plugin</i> <b>Supsystic Contact Form</b> with Software Link related to
   * Wordpress site and present in SVN but no tag related. Expected to be downloaded from software
   * link
   */
  @Test
  public void genConfigurationPluginFromSoftwareLink() throws IOException {
    var edbID = 49544L;
    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("PLUGIN_NAME=contact-form-by-supsystic"));
  }

  /**
   * Exploit Wordpress <i>Theme</i> <b>Fruitful</b> with Software Link related to Wordpress site,
   * and present in SVN.
   */
  @Test
  public void genConfigurationTheme() throws IOException {
    final var edbID = 48083L;
    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("THEME_NAME=fruitful"));
    FileUtils.deleteDirectory(dir);
  }

  /**
   * Exploit Wordpress <i>Theme</i> <b>Beaty and Premium</b> with no Software Link related to
   * Wordpress site but with Vulnerable App.
   */
  @Test
  public void genConfigurationThemeWithVulnerableApp() throws IOException {
    final var edbID = 39552L;
    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("THEME_NAME=beauty-&-clean"));
    FileUtils.deleteDirectory(dir);
  }

  /** Exploit Wordpress <i>Core</i> with Software Link, but this should not be used. */
  @Test
  public void genConfigurationCore() throws IOException {
    final var edbID = 47557L;
    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("WORDPRESS_VERSION=5.2.4"));
    FileUtils.deleteDirectory(dir);
  }

  /** Exploit Wordpress <i>Core</i> with 2 versions 4.7.0/4.7.1. */
  @Test
  public void genConfigurationCore2Version() throws IOException {
    final var edbID = 41224L;
    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("WORDPRESS_VERSION=4.7.1"));
    FileUtils.deleteDirectory(dir);
  }
}
