package com.lprevidente.edb2docker.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lprevidente.edb2docker.TestBase;
import com.lprevidente.edb2docker.entity.pojo.WordpressType;
import com.lprevidente.edb2docker.entity.pojo.docker.DockerCompose;
import com.lprevidente.edb2docker.exception.NoVulnerableAppException;
import com.lprevidente.edb2docker.utility.ConfigurationUtils;
import lombok.NonNull;
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

    assertDoesNotThrow(() -> service.genConfiguration(edbID, false));
    FileUtils.deleteDirectory(dir);
  }

  /**
   * Exploit Wordpress <i>Plugin</i> <b>Form Maker</b> with Software Link related to Wordpress site
   */
  @Test
  public void genConfigurationPluginFormMaker() throws IOException {
    final var edbID = 44559L;
    assertDoesNotThrow(() -> service.genConfiguration(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    assertTrue(testContentDockercompose(dir, WordpressType.PLUGIN, "form-maker"));
    FileUtils.deleteDirectory(dir);
  }

  /**
   * Exploit Wordpress <i>Plugin</i> <b>WP Paginate</b> with Software Link related to Wordpress site
   */
  @Test
  public void genConfigurationPluginWPPaginate() throws IOException {
    final var edbID = 49355L;
    assertDoesNotThrow(() -> service.genConfiguration(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    assertTrue(testContentDockercompose(dir, WordpressType.PLUGIN, "wp-paginate"));
    FileUtils.deleteDirectory(dir);
  }

  /**
   * Exploit Wordpress <i>Plugin</i> <b>ColorBox</b> with Software Link related to Wordpress site
   */
  @Test
  public void genConfigurationPluginColorbox() throws IOException {
    final var edbID = 48919L;
    assertDoesNotThrow(() -> service.genConfiguration(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    assertTrue(testContentDockercompose(dir, WordpressType.PLUGIN, "wp-colorbox"));
    FileUtils.deleteDirectory(dir);
  }

  /**
   * Exploit Wordpress <i>Plugin</i> <b>Easy Contact Form</b> with no Software Link related to
   * Wordpress site and present in SVN but no tag related. Expected Exploit Unsupported Exception
   */
  @Test
  public void genConfigurationPluginEasyContactForm() {
    final var edbID = 49427L;
    assertThrows(NoVulnerableAppException.class, () -> service.genConfiguration(edbID, false));
  }

  /**
   * Exploit Wordpress <i>Plugin</i> <b>Supsystic Contact Form</b> with Software Link related to
   * Wordpress site and present in SVN but no tag related. Expected to be downloaded from software
   * link
   */
  @Test
  public void genConfigurationPluginFromSoftwareLink() throws IOException {
    var edbID = 49544L;
    assertDoesNotThrow(() -> service.genConfiguration(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    assertTrue(testContentDockercompose(dir, WordpressType.PLUGIN, "contact-form-by-supsystic"));
    FileUtils.deleteDirectory(dir);
  }

  /**
   * Exploit Wordpress <i>Theme</i> <b>Fruitful</b> with Software Link related to Wordpress site,
   * and present in SVN.
   */
  @Test
  public void genConfigurationTheme() throws IOException {
    final var edbID = 48083L;
    assertDoesNotThrow(() -> service.genConfiguration(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    assertTrue(testContentDockercompose(dir, WordpressType.THEME, "fruitful"));
    FileUtils.deleteDirectory(dir);
  }

  /**
   * Exploit Wordpress <i>Theme</i> <b>Beaty and Premium</b> with no Software Link related to
   * Wordpress site but with Vulnerable App.
   */
  @Test
  public void genConfigurationThemeWithVulnerableApp() throws IOException {
    final var edbID = 39552L;
    assertDoesNotThrow(() -> service.genConfiguration(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    assertTrue(testContentDockercompose(dir, WordpressType.THEME, "beauty-&-clean"));
    FileUtils.deleteDirectory(dir);
  }

  /** Exploit Wordpress <i>Core</i> with Software Link, but this should not be used. */
  @Test
  public void genConfigurationCore() throws IOException {
    final var edbID = 47557L;
    assertDoesNotThrow(() -> service.genConfiguration(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    assertTrue(testContentDockercompose(dir, WordpressType.CORE, "5.2.4"));
    FileUtils.deleteDirectory(dir);
  }

  /** Exploit Wordpress <i>Core</i> with 2 versions 4.7.0/4.7.1. */
  @Test
  public void genConfigurationCore2Version() throws IOException {
    final var edbID = 41224L;
    assertDoesNotThrow(() -> service.genConfiguration(edbID, false));

    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    assertTrue(testContentDockercompose(dir, WordpressType.CORE, "4.7.1"));
    FileUtils.deleteDirectory(dir);
  }

  private boolean testContentDockercompose(
      @NonNull File exploitDir, @NonNull WordpressType type, @NonNull String toCompare) {
    try {
      //  Read Docker-compose
      final var yamlFactory = ConfigurationUtils.getYAMLFactoryDockerCompose();

      ObjectMapper om = new ObjectMapper(yamlFactory);
      final var dockerCompose =
          om.readValue(new File(exploitDir + "/docker-compose.yml"), DockerCompose.class);

      if (type.equals(WordpressType.CORE))
        return dockerCompose.getServices().get("wp").getImage().equals("wordpress:" + toCompare);
      else {
        String volume =
            String.format(
                "./%ss/%s/:/var/www/html/wp-content/%ss/%s",
                type.name().toLowerCase(), toCompare, type.name().toLowerCase(), toCompare);
        return dockerCompose.getServices().get("wp").getVolumes().contains(volume)
            && dockerCompose.getServices().get("wpcli").getVolumes().contains(volume);
      }
    } catch (IOException e) {
      e.printStackTrace();
      return false;
    }
  }
}
