package com.lprevidente.cve2docker.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lprevidente.cve2docker.entity.pojo.*;
import com.lprevidente.cve2docker.entity.pojo.docker.DockerCompose;
import com.lprevidente.cve2docker.entity.vo.dockerhub.SearchTagVO;
import com.lprevidente.cve2docker.exception.*;
import com.lprevidente.cve2docker.utility.ConfigurationUtils;
import com.lprevidente.cve2docker.utility.Utils;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.expression.ParseException;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import static com.lprevidente.cve2docker.entity.pojo.JoomlaType.CORE;
import static com.lprevidente.cve2docker.utility.Utils.isNotEmpty;
import static org.apache.commons.io.FileUtils.readFileToString;
import static org.apache.commons.io.FileUtils.write;
import static org.apache.commons.lang3.StringUtils.*;

@Slf4j
@Service
public class JoomlaService implements IGenerateService {

  @Autowired @Lazy private SystemCve2Docker systemCve2Docker;

  @Value("${spring.config.exploits-dir}")
  private String EXPLOITS_DIR;

  @Value("${spring.config.joomla.config-dir}")
  private String CONFIG_DIR;

  @Value("${spring.config.joomla.endpoint-to-test}")
  private String ENDPOINT_TO_TEST;

  private static final Pattern PATTERN_CORE_JOOMLA =
      Pattern.compile(
          "Joomla!?\\s(?:Core\\s)?(<(?:\\s))?(\\d(?:\\.[\\d|x]+)(?:\\.[\\d|x]+)?)(?:\\s)?(\\/|<)?(?:\\s)?(\\d(?:\\.[\\d|x]+)(?:\\.[\\d|x])?)?\\s-",
          Pattern.CASE_INSENSITIVE);

  private final String[] filenames =
      new String[] {
        "start.sh",
        "setup.sh",
        "config/mysql/init.sql",
        "config/joomla/configuration.php",
        "config/joomla/install-joomla-extension.php"
      };

  private final Long MAX_TIME_TEST;

  public JoomlaService(@Value("${spring.config.joomla.max-time-test}") Integer MAX_TIME_TEST) {
    this.MAX_TIME_TEST = TimeUnit.MINUTES.toMillis(MAX_TIME_TEST);
  }

  @Override
  public boolean canHandle(@NonNull ExploitDB exploitDB) {
    return containsIgnoreCase(exploitDB.getTitle(), ExploitType.JOOMLA.name())
        && !containsIgnoreCase(exploitDB.getTitle(), ExploitType.WORDPRESS.name());
  }

  /**
   * Method to generate configuration for the exploit related to <b>Joomla</b>. The configuration
   * consist in docker-compose, env file e other files depending on the exploit type.
   *
   * <p>The configuration is saved in ./content/generated/{edbID} folder.
   *
   * @param exploit not null
   * @param removeConfig if true the configuration will be removed after it has been setup.
   * @throws ParseExploitException throws when it is not possible to extrapolate the type or version
   *     of the exploit
   * @throws ImageNotFoundException throws when there is no image related to joomla core
   * @throws NoVulnerableAppException throws when there isn't a vulnerable app for the exploit
   * @throws ExploitUnsupported throws when there is no possibility to generate the configuration.
   * @throws ConfigurationException throws when there is a problem during the setup or test of the
   *     configuration.
   */
  @Override
  public void genConfiguration(@NonNull ExploitDB exploit, boolean removeConfig)
      throws GenerationException {
    log.info("Generating configuration for Joomla Exploit");

    String versionJoomla = null;
    File exploitDir = null;
    JoomlaType type;

    // First check if it is related to Joomla Core
    final var matcher = PATTERN_CORE_JOOMLA.matcher(exploit.getTitle());
    try {
      exploitDir = Utils.createDir(EXPLOITS_DIR + "/" + exploit.getId());

      if (matcher.find()) {
        type = CORE;
        // Extracting the versions
        //  final var less = matcher.group(1);
        final var firstVersion = matcher.group(2);
        // final var separator = matcher.group(3); // / or <
        final var secondVersion = matcher.group(4);

        SearchTagVO.TagVO tag = null;

        // Search a WordPress image with a version equal to the first Version
        if (isNotBlank(firstVersion)) tag = findTag(Version.parse(firstVersion));

        // If no tag has been found, then search with the second Version
        if (tag == null && isNotBlank(secondVersion)) tag = findTag(Version.parse(secondVersion));

        // If no tag has been found and there is no first and second version, throw an error.
        if (tag == null && isBlank(firstVersion) && isBlank(secondVersion))
          throw new ParseExploitException("No version found in " + exploit.getTitle());

        if (tag != null) versionJoomla = tag.getName();
        else throw new ImageNotFoundException("Joomla!");

      } else {
        if (exploit.getFilenameVulnApp() != null) {
          type = JoomlaType.COMPONENT;
          log.info("Trying to download from ExploitDB");
          final var zipFile = new File(exploitDir, "/component/" + exploit.getFilenameVulnApp());
          systemCve2Docker.downloadVulnApp(exploit.getFilenameVulnApp(), zipFile);
          if (isNotEmpty(zipFile)) log.info("Download completed");
          else log.warn("Zip file is empty or corrupted");
        } else throw new NoVulnerableAppException();
      }

      // Copy All necessary files
      copyContent(exploitDir, type, exploit.getFilenameVulnApp(), versionJoomla);
      log.info("Configuration created. Trying to configure it");

      String[] cmdSetup =
          type == CORE
              ? new String[] {"sh", "setup.sh"}
              : new String[] {"sh", "setup.sh", exploit.getFilenameVulnApp()};
      // Setup
      ConfigurationUtils.setupConfiguration(
          exploitDir, ENDPOINT_TO_TEST, MAX_TIME_TEST, removeConfig, cmdSetup);
      log.info("Container configured correctly!");

      cleanDirectory(exploitDir);
    } catch (IOException e) {
      // In case of error, delete the main directory in order to not leave traces
      if (Objects.nonNull(exploitDir)) {
        try {
          FileUtils.deleteDirectory(exploitDir);
        } catch (IOException ignored) {
        }
      }
      throw new GenerationException("An IO Exception occurred", e);
    } catch (GenerationException e) {
      // In case of error, delete the main directory in order to not leave traces
      try {
        FileUtils.deleteDirectory(exploitDir);
      } catch (IOException ignored) {
      }
      throw e;
    }
  }

  /**
   * Find a Docker Tag that is compatible with the specific version of joomla provided
   *
   * @param version the version of Joomla
   * @return null if no tag has been found.
   * @throws IOException exception occurred during the request to dockerhub
   */
  private SearchTagVO.TagVO findTag(@NonNull Version version) throws IOException {
    if (version.getNumberOfComponents() < 3) version.setNumberOfComponents(3);
    // Doesn't exist a docker image before 3.4
    if (version.compareTo(Version.parse("3.4.0")) < 0) return null;

    final var cpe = new CPE("2.3", CPE.Part.APPLICATION, "joomla", "joomla%5c!", version);

    return systemCve2Docker.findTag(
        cpe,
        (_t, cpeMatchVO) ->
            cpeMatchVO.getCpe().getVersion().getPattern().matcher(_t.getName()).matches(),
        (_t, cpeMatchVO) ->
            cpeMatchVO.getCpe().getVersion().getPattern().matcher(_t.getName()).find());
  }

  /**
   * Copy the content from the configuration directory into the directory provided. Also modifies
   * the env file inserting the name of Joomla component.
   *
   * @param baseDir the directory in which the files should be copied. component the name of Joomla
   *     component.
   * @param component the name of joomla component
   * @throws IOException if the file provided is not a directory or an error during the copy
   *     process.
   */
  private void copyContent(
      @NonNull File baseDir, @NonNull JoomlaType type, String component, String version)
      throws IOException {

    ConfigurationUtils.copyFiles(CONFIG_DIR, baseDir, filenames);

    // Copy the env file and append the component name
    var env = new File(baseDir, ".env");
    var contentEnv =
        IOUtils.toString(ConfigurationUtils.getBufferedReaderResource(CONFIG_DIR + "/.env"));

    //  Read Docker-compose
    final var yamlFactory = ConfigurationUtils.getYAMLFactoryDockerCompose();

    ObjectMapper om = new ObjectMapper(yamlFactory);
    final var dockerCompose =
        om.readValue(
            ConfigurationUtils.getBufferedReaderResource(CONFIG_DIR + "/docker-compose.yml"),
            DockerCompose.class);

    switch (type) {
      case CORE:
        contentEnv = contentEnv.replace("3.9.24", version);
        break;
      case COMPONENT:
        contentEnv += "\nCOMPONENT_NAME=" + component;
        dockerCompose
            .getServices()
            .get("joomla")
            .getVolumes()
            .add("./component/${COMPONENT_NAME}:/var/www/html/work_directory/${COMPONENT_NAME}");
        break;
    }

    write(env, contentEnv, StandardCharsets.UTF_8);
    om.writeValue(new File(baseDir, "docker-compose.yml"), dockerCompose);
  }

  /**
   * Clean the exploit directory deleting all unnecessary files
   *
   * @param exploitDir not null
   */
  public void cleanDirectory(@NonNull File exploitDir) {
    try {
      // Remove files
      FileUtils.deleteDirectory(new File(exploitDir, "config/mysql"));
      FileUtils.forceDelete(new File(exploitDir, "config/joomla/install-joomla-extension.php"));
      FileUtils.forceDelete(new File(exploitDir, "setup.sh"));
      FileUtils.forceDelete(new File(exploitDir, "start.sh"));
      FileUtils.deleteDirectory(new File(exploitDir, "component"));

      final var yamlFactory = ConfigurationUtils.getYAMLFactoryDockerCompose();

      // Remove directory and files also from docker-compose
      ObjectMapper om = new ObjectMapper(yamlFactory);
      final var dockerCompose =
          om.readValue(new File(exploitDir, "docker-compose.yml"), DockerCompose.class);

      dockerCompose
          .getServices()
          .get("joomla")
          .getVolumes()
          .removeIf(
              volume ->
                  volume.contains("joomla/mysql")
                      || volume.contains("install-joomla-extension.php")
                      || volume.contains("./component/"));
      om.writeValue(new File(exploitDir, "docker-compose.yml"), dockerCompose);
    } catch (IOException ignored) {

    }
  }
}
