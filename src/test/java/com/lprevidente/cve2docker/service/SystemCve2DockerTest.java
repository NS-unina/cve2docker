package com.lprevidente.cve2docker.service;

import com.lprevidente.cve2docker.TestBase;
import com.lprevidente.cve2docker.entity.model.*;
import com.lprevidente.cve2docker.exception.ConfigurationNotSupported;
import com.lprevidente.cve2docker.exception.ProcessException;
import com.lprevidente.cve2docker.repository.ExplConfigRepository;
import com.lprevidente.cve2docker.repository.ExploitDBRepository;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

@Slf4j
public class SystemCve2DockerTest extends TestBase {

  @Autowired private SystemCve2Docker service;

  @Autowired private ExplConfigRepository explConfigRepository;

  @Autowired private ExploitDBRepository exploitDBRepository;

  @Test
  public void updateExploitDB() {
    service.updateExploitDB();
    final var all = exploitDBRepository.findAll();
    assertNotNull(all);
    assertTrue(all.stream().anyMatch(_expl -> _expl.getIdVulnApp() != null));
  }

  @Test
  public void updateExploitConfigurations() {
    explConfigRepository.deleteAll();
    service.updateExploitConfigurations();
    final var all = explConfigRepository.findAll();
    assertNotNull(all);
    assertNotNull(
        all.stream().filter(config -> config instanceof GitHubConfig).findFirst().orElse(null));
    assertNotNull(
        all.stream().filter(config -> config instanceof DockerHubConfig).findFirst().orElse(null));
  }

  @Test
  public void getConfigurationsAlreadyPresent() {
    assertDoesNotThrow(
        () -> {
          final var configurations = service.getConfigurations("2018-1111");
          assertFalse(configurations.isEmpty());
          assertTrue(configurations.size() >= 3);
          assertTrue(configurations.stream().anyMatch(_c -> _c instanceof DockerHubConfig));
          assertTrue(configurations.stream().anyMatch(_c -> _c instanceof GitHubConfig));
        });
  }

  @Test
  public void getConfigurationsWithVulnApp() {
    assertDoesNotThrow(
        () -> {
          final var configurations = service.getConfigurations("2020-10220");
          assertFalse(configurations.isEmpty());
          assertTrue(configurations.stream().anyMatch(_c -> _c instanceof GeneratedConfig));
          configurations.forEach(
              _config -> {
                assertNotNull(_config.getCve());

                var _genConfig = (GeneratedConfig) _config;
                assertNotNull(_genConfig.getDockerfile());
                log.debug(_genConfig.getDockerfile().generateDockerfile());
              });
        });
  }

  @Test
  public void genConfigurationNotPresent() {

    final var configurations = service.getConfigurations("2020-29471");
    configurations.forEach(
        _config -> {
          assertNotNull(_config.getCve());
          var _genConfig = (GeneratedConfig) _config;
          assertNotNull(_genConfig.getDockerfile());
          log.debug(_genConfig.getDockerfile().generateDockerfile());
          explConfigRepository.delete(_config);
        });
  }

  @Test
  public void genConfigurationFromExploitWordpressPlugin() throws IOException {
    var edbID = "44559";
    File dir = new File("./content/" + edbID);
    if (dir.exists()) dir.delete();

    service.genConfigurationFromExploit(edbID);

    dir = new File("./content/" + edbID);
    assertTrue(dir.exists());

    // Check that there is the 'plugin' directory with the folder
    // corresponding to the downloaded plugin inside
    var pluginDir = new File(dir, "/plugin/");
    assertTrue(pluginDir.exists());
    var files = pluginDir.listFiles();
    assertNotNull(files);
    assertEquals(1, files.length);

    // Check there is a docker-compose
    var file = new File(dir, "/docker-compose.yml");
    assertTrue(file.exists());

    var env = new File(dir, "/.env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("PLUGIN_NAME=form-maker"));
  }

  @Test
  public void genConfigurationFromExploitWordpressTheme() throws IOException {
    var edbID = "48083";
    File dir = new File("./content/" + edbID);
    if (dir.exists()) dir.delete();


    service.genConfigurationFromExploit(edbID);

    dir = new File("./content/" + edbID);
    assertTrue(dir.exists());

    // Check that there is the 'theme' directory with the folder
    // corresponding to the downloaded theme inside
    var pluginDir = new File(dir, "/theme/");
    assertTrue(pluginDir.exists());
    var files = pluginDir.listFiles();
    assertNotNull(files);
    assertEquals(1, files.length);

    // Check there is a docker-compose
    var file = new File(dir, "/docker-compose.yml");
    assertTrue(file.exists());

    var env = new File(dir, "/.env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("THEME_NAME=fruitful"));
  }

  @Test
  public void genConfigurationFromExploitWordpressThemeNoSVN() throws IOException {
    var edbID = "39552";
    File dir = new File("./content/" + edbID);
    if (dir.exists()) dir.delete();

    service.genConfigurationFromExploit(edbID);

    dir = new File("./content/" + edbID);
    assertTrue(dir.exists());

    // Check that there is the 'theme' directory with the folder
    // corresponding to the downloaded theme inside
    var pluginDir = new File(dir, "/theme/");
    assertTrue(pluginDir.exists());
    var files = pluginDir.listFiles();
    assertNotNull(files);
    assertEquals(1, files.length);

    // Check there is a docker-compose
    var file = new File(dir, "/docker-compose.yml");
    assertTrue(file.exists());

    var env = new File(dir, "/.env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("THEME_NAME=beauty-&-clean/beauty-premium"));
  }

  @Test
  public void genConfigurationFromExploitWordpressCore() throws IOException {

    var edbID = "47557";
    File dir = new File("./content/" + edbID);
    if (dir.exists()) dir.delete();

    service.genConfigurationFromExploit(edbID);

    dir = new File("./content/" + edbID);
    assertTrue(dir.exists());

    // Check there is a docker-compose
    var file = new File(dir, "/docker-compose.yml");
    assertTrue(file.exists());

    var env = new File(dir, "/.env");
    final var envContent = FileUtils.readFileToString(env, StandardCharsets.UTF_8);
    assertTrue(envContent.contains("WORDPRESS_VERSION=5.2.4"));

  }

  @Test
  public void genConfigurationFromExploitWordpressCore2Version() {
    service.genConfigurationFromExploit("29598");
  }
}
