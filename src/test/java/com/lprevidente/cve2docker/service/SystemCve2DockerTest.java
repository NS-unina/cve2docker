package com.lprevidente.cve2docker.service;

import com.lprevidente.cve2docker.TestBase;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

@Slf4j
public class SystemCve2DockerTest extends TestBase {

  @Value("${spring.config.exploits-dir}")
  private String BASE_DIR;

  @Autowired private SystemCve2Docker service;

  @Test
  public void genConfigurationFromExploitWordpressPlugin() throws IOException {
    var edbID = "44559";
    File dir = new File(BASE_DIR + "/" + edbID);
    dir.delete();

    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID));
    assertTrue(dir.exists());

    // Check that there is the 'plugin' directory with the folder
    // corresponding to the downloaded plugin inside
    var pluginDir = new File(dir, "plugins/");
    assertTrue(pluginDir.exists());
    var files = pluginDir.listFiles();
    assertNotNull(files);
    assertEquals(1, files.length);

    // Check there is a docker-compose
    var file = new File(dir, "docker-compose.yml");
    assertTrue(file.exists());

    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("PLUGIN_NAME=form-maker"));
  }

  @Test
  public void genConfigurationFromExploitWordpressTheme() throws IOException {
    var edbID = "48083";
    File dir = new File(BASE_DIR + "/" + edbID);
    dir.delete();

    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID));

    // dir = new File("./content/" + edbID);
    assertTrue(dir.exists());

    // Check that there is the 'theme' directory with the folder
    // corresponding to the downloaded theme inside
    var pluginDir = new File(dir, "themes/");
    assertTrue(pluginDir.exists());
    var files = pluginDir.listFiles();
    assertNotNull(files);
    assertEquals(1, files.length);

    // Check there is a docker-compose
    var file = new File(dir, "docker-compose.yml");
    assertTrue(file.exists());

    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("THEME_NAME=fruitful"));
  }

  @Test
  public void genConfigurationFromExploitWordpressThemeNoSVN() throws IOException {
    var edbID = "39552";
    File dir = new File(BASE_DIR + "/" + edbID);
    dir.delete();

    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID));
    assertTrue(dir.exists());

    // Check that there is the 'theme' directory with the folder
    // corresponding to the downloaded theme inside
    var pluginDir = new File(dir, "themes/");
    assertTrue(pluginDir.exists());
    var files = pluginDir.listFiles();
    assertNotNull(files);
    assertEquals(1, files.length);

    // Check there is a docker-compose
    var file = new File(dir, "docker-compose.yml");
    assertTrue(file.exists());

    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("THEME_NAME=beauty-&-clean/beauty-premium"));
  }

  @Test
  public void genConfigurationFromExploitWordpressCore() throws IOException {

    final var edbID = "47557";
    File dir = new File(BASE_DIR + "/" + edbID);
    dir.delete();

    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID));
    assertTrue(dir.exists());

    // Check there is a docker-compose
    var file = new File(dir, "docker-compose.yml");
    assertTrue(file.exists());

    var env = new File(dir, ".env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("WORDPRESS_VERSION=5.2.4"));
  }

  @Test
  public void genConfigurationFromExploitWordpressCore2Version() {
    final var edbID = "29598";
    File dir = new File(BASE_DIR + "/" + edbID);
    dir.delete();

    assertDoesNotThrow(() -> service.genConfigurationFromExploit(edbID));
  }
}
