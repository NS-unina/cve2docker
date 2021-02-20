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

public class JoomlaServiceTest extends TestBase {

  @Value("${spring.config.exploits-dir}")
  private String EXPLOITS_DIR;

  @Autowired
  private SystemCve2Docker service;


  /** Exploit Joomla <i>Component</i> JS Job with VulnApp. */
  @Test
  public void genConfigurationComponentJsJob() throws IOException {
    final var edbID = "47232";
    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    FileUtils.deleteDirectory(dir);

    assertDoesNotThrow(() -> service.genConfigurationFromExploit((Long.parseLong(edbID)), false));

    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("COMPONENT_NAME=b8df21a9bed50ce4ee1681e0077e3b5d-jsjobs.zip"));
  }

  /** Exploit Joomla <i>Component</i> Easy Shop with VulnApp. */
  @Test
  public void genConfigurationComponentEasyShop() throws IOException {
    final var edbID = "46219";
    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    FileUtils.deleteDirectory(dir);

    assertDoesNotThrow(() -> service.genConfigurationFromExploit((Long.parseLong(edbID)), false));

    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(
        envContent.contains(
            "COMPONENT_NAME=cba36c9f7233ca178bc62bf0bd41115d-com_easyshop-v1.2.3.zip"));
  }

  /** Exploit Joomla <i>Component</i> Proclaim with VulnApp. */
  @Test
  public void genConfigurationComponentProclaim() throws IOException {
    final var edbID = "44164";
    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    FileUtils.deleteDirectory(dir);

    assertDoesNotThrow(() -> service.genConfigurationFromExploit((Long.parseLong(edbID)), false));

    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(
        envContent.contains("COMPONENT_NAME=6ac663f3794ba28f8c736c2881e44b1e-pkg_proclaim.zip"));
  }

  /** Exploit Joomla <i>Component</i> Google Map Landkarten with VulnApp. */
  @Test
  public void genConfigurationComponentGoogleMapLandkarten() throws IOException {
    final var edbID = "44113";
    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    FileUtils.deleteDirectory(dir);

    assertDoesNotThrow(() -> service.genConfigurationFromExploit((Long.parseLong(edbID)), false));

    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(
        envContent.contains("COMPONENT_NAME=75b746a6c5cf1caa4aa1348f19247562-com_gmap_4.2.3.zip"));
  }

  /** Exploit Joomla <i>Component</i> no VulnApp. */
  @Test
  public void genConfigurationNoVulnApp() throws IOException {
    final var edbID = "48202";
    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    FileUtils.deleteDirectory(dir);

    assertThrows(ExploitUnsupported.class, () -> service.genConfigurationFromExploit((Long.parseLong(edbID)), false));
  }
}
