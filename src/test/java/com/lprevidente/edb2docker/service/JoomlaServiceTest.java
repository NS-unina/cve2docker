package com.lprevidente.edb2docker.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lprevidente.edb2docker.TestBase;
import com.lprevidente.edb2docker.entity.pojo.docker.DockerCompose;
import com.lprevidente.edb2docker.exception.ImageNotFoundException;
import com.lprevidente.edb2docker.exception.NoVulnerableAppException;
import com.lprevidente.edb2docker.utility.ConfigurationUtils;
import lombok.NonNull;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.io.File;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

public class JoomlaServiceTest extends TestBase {

  @Value("${spring.config.exploits-dir}")
  private String EXPLOITS_DIR;

  @Autowired private SystemCve2Docker service;

  /** Exploit Joomla <i>Component</i> JS Job with VulnApp. */
  @Test
  public void genConfigurationComponentJsJob() throws IOException {
    final var edbID = 47232L;
    assertDoesNotThrow(() -> service.genConfiguration(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    FileUtils.deleteDirectory(dir);
  }

  /** Exploit Joomla <i>Component</i> Easy Shop with VulnApp. */
  @Test
  public void genConfigurationComponentEasyShop() throws IOException {
    final var edbID = 46219L;
    assertDoesNotThrow(() -> service.genConfiguration(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    FileUtils.deleteDirectory(dir);
  }

  /** Exploit Joomla <i>Component</i> Proclaim with VulnApp. */
  @Test
  public void genConfigurationComponentProclaim() throws IOException {
    final var edbID = 44164L;
    assertDoesNotThrow(() -> service.genConfiguration(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    FileUtils.deleteDirectory(dir);
  }

  /** Exploit Joomla <i>Component</i> Google Map Landkarten with VulnApp. */
  @Test
  public void genConfigurationComponentGoogleMapLandkarten() throws IOException {
    final var edbID = 44113L;
    assertDoesNotThrow(() -> service.genConfiguration(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    FileUtils.deleteDirectory(dir);
  }

  /** Exploit Joomla <i>Component</i> no VulnApp. */
  @Test
  public void genConfigurationNoVulnApp() {
    final var edbID = 48202L;

    assertThrows(NoVulnerableAppException.class, () -> service.genConfiguration(edbID, false));
  }

  /** Exploit Joomla <i>Core - 3.6.4</i> with Docker image and NO reference to Core. */
  @Test
  public void genConfigurationCoreWithImage() throws IOException {
    final var edbID = 41157L;
    assertDoesNotThrow(() -> service.genConfiguration(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    assertTrue(testContentDockercompose(dir, "3.6.4"));
    FileUtils.deleteDirectory(dir);
  }

  /** Exploit Joomla <i>Core - 2.5.2</i> with NO Docker image. */
  @Test
  public void genConfigurationCoreWithNoImage() {
    final var edbID = 41156L;

    assertThrows(ImageNotFoundException.class, () -> service.genConfiguration(edbID, false));
  }

  /** Exploit Joomla <i>Core - 3.9.1</i> with reference to Core Docker image. */
  @Test
  public void genConfigurationCoreWithReference() throws IOException {
    final var edbID = 46200L;
    assertDoesNotThrow(() -> service.genConfiguration(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    assertTrue(testContentDockercompose(dir, "3.9.1"));
    FileUtils.deleteDirectory(dir);
  }

  private boolean testContentDockercompose(@NonNull File exploitDir, @NonNull String version) {
    try {
      //  Read Docker-compose
      final var yamlFactory = ConfigurationUtils.getYAMLFactoryDockerCompose();

      ObjectMapper om = new ObjectMapper(yamlFactory);
      final var dockerCompose =
          om.readValue(new File(exploitDir + "/docker-compose.yml"), DockerCompose.class);
      return dockerCompose.getServices().get("joomla").getImage().equals("joomla:" + version);
    } catch (IOException e) {
      e.printStackTrace();
      return false;
    }
  }
}
