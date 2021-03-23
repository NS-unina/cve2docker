package com.lprevidente.edb2docker.service;

import com.lprevidente.edb2docker.TestBase;
import com.lprevidente.edb2docker.exception.ImageNotFoundException;
import com.lprevidente.edb2docker.exception.NoVulnerableAppException;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

public class JoomlaServiceTest extends TestBase {

  @Value("${spring.config.exploits-dir}")
  private String EXPLOITS_DIR;

  @Autowired private SystemCve2Docker service;

  /** Exploit Joomla <i>Component</i> JS Job with VulnApp. */
  @Test
  public void genConfigurationComponentJsJob() throws IOException {
    final var edbID = 47232L;
    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("COMPONENT_NAME=b8df21a9bed50ce4ee1681e0077e3b5d-jsjobs.zip"));
    FileUtils.deleteDirectory(dir);
  }

  /** Exploit Joomla <i>Component</i> Easy Shop with VulnApp. */
  @Test
  public void genConfigurationComponentEasyShop() throws IOException {
    final var edbID = 46219L;
    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(
        envContent.contains(
            "COMPONENT_NAME=cba36c9f7233ca178bc62bf0bd41115d-com_easyshop-v1.2.3.zip"));
    FileUtils.deleteDirectory(dir);
  }

  /** Exploit Joomla <i>Component</i> Proclaim with VulnApp. */
  @Test
  public void genConfigurationComponentProclaim() throws IOException {
    final var edbID = 44164L;
    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(
        envContent.contains("COMPONENT_NAME=6ac663f3794ba28f8c736c2881e44b1e-pkg_proclaim.zip"));
    FileUtils.deleteDirectory(dir);
  }

  /** Exploit Joomla <i>Component</i> Google Map Landkarten with VulnApp. */
  @Test
  public void genConfigurationComponentGoogleMapLandkarten() throws IOException {
    final var edbID = 44113L;
    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(
        envContent.contains("COMPONENT_NAME=75b746a6c5cf1caa4aa1348f19247562-com_gmap_4.2.3.zip"));
    FileUtils.deleteDirectory(dir);
  }

  /** Exploit Joomla <i>Component</i> no VulnApp. */
  @Test
  public void genConfigurationNoVulnApp() {
    final var edbID = 48202L;

    assertThrows(
        NoVulnerableAppException.class, () -> service.genConfigurationFromExploit(edbID, false));
  }

  /** Exploit Joomla <i>Core - 3.6.4</i> with Docker image and NO reference to Core. */
  @Test
  public void genConfigurationCoreWithImage() throws IOException {
    final var edbID = 41157L;
    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("JOOMLA_VERSION=3.6.4"));
    FileUtils.deleteDirectory(dir);
  }

  /** Exploit Joomla <i>Core - 2.5.2</i> with NO Docker image. */
  @Test
  public void genConfigurationCoreWithNoImage() {
    final var edbID = 41156L;

    assertThrows(ImageNotFoundException.class, () -> service.genConfigurationFromExploit(edbID, false));
  }

  /** Exploit Joomla <i>Core - 3.9.1</i> with reference to Core Docker image. */
  @Test
  public void genConfigurationCoreWithReference() throws IOException {
    final var edbID = 46200L;
    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("JOOMLA_VERSION=3.9.1"));
    FileUtils.deleteDirectory(dir);
  }
}
