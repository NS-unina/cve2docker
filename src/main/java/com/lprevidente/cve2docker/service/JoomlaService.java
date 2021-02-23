package com.lprevidente.cve2docker.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lprevidente.cve2docker.entity.pojo.CPE;
import com.lprevidente.cve2docker.entity.pojo.ExploitDB;
import com.lprevidente.cve2docker.entity.pojo.JoomlaType;
import com.lprevidente.cve2docker.entity.pojo.Version;
import com.lprevidente.cve2docker.entity.pojo.docker.DockerCompose;
import com.lprevidente.cve2docker.entity.vo.dockerhub.SearchTagVO;
import com.lprevidente.cve2docker.exception.ConfigurationException;
import com.lprevidente.cve2docker.exception.ExploitUnsupported;
import com.lprevidente.cve2docker.utility.ConfigurationUtils;
import com.lprevidente.cve2docker.utility.Utils;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.expression.ParseException;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import static org.apache.commons.io.FileUtils.readFileToString;
import static org.apache.commons.io.FileUtils.write;
import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

@Slf4j
@Service
public class JoomlaService {

  @Autowired private SystemCve2Docker systemCve2Docker;

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

  private final Long MAX_TIME_TEST;

  public JoomlaService(@Value("${spring.config.joomla.max-time-test}") Integer MAX_TIME_TEST) {
    this.MAX_TIME_TEST = TimeUnit.MINUTES.toMillis(MAX_TIME_TEST);
  }

  @PostConstruct
  public void checkConfig() throws BeanCreationException {
    var dir = new File(CONFIG_DIR);

    if (!dir.exists() || !dir.isDirectory())
      throw new BeanCreationException("No Joomla! config dir present in " + CONFIG_DIR);

    var filenames =
        new String[] {
          "docker-compose.yml",
          "start.sh",
          "setup.sh",
          ".env",
          "config/mysql/init.sql",
          "config/joomla/configuration.php",
          "config/joomla/install-joomla-extension.php"
        };

    for (var filename : filenames) {
      var file = new File(dir, filename);
      if (!file.exists())
        throw new BeanCreationException("No " + file.getName() + " present in " + CONFIG_DIR);
    }
  }

  /**
   * Method to generate configuration for the exploit related to <b>Joomla</b>. The configuration
   * consist in docker-compose, env file e other files depending on the exploit type.
   *
   * <p>The configuration is saved in ./content/generated/{edbID} folder.
   *
   * @param exploit not null
   * @param removeConfig if true the configuration will be removed after it has been setup.
   * @throws ExploitUnsupported throws when there is no possibility to generate the configuration.
   * @throws IOException throw when there is a problem with I/O operation
   * @throws ConfigurationException throws when there is a problem during the setup or test of the
   *     configuration.
   */
  public void genConfiguration(@NonNull ExploitDB exploit, boolean removeConfig)
      throws ExploitUnsupported, IOException, ConfigurationException {
    log.info("Generating configuration for Joomla Exploit");

    String versionJoomla = null;
    File exploitDir;
    JoomlaType type;

    // First check if it is related to Joomla Core
    final var matcher = PATTERN_CORE_JOOMLA.matcher(exploit.getTitle());

    if (matcher.find()) {
      type = JoomlaType.CORE;
      // Extracting the versions
     //  final var less = matcher.group(1);
      final var firstVersion = matcher.group(2);
      // final var separator = matcher.group(3); // / or <
      final var secondVersion = matcher.group(4);

      SearchTagVO.TagVO tag = null;
      try {
        if (isNotBlank(firstVersion)) tag = findTag(Version.parse(firstVersion));
        if (tag == null && isNotBlank(secondVersion)) tag = findTag(Version.parse(secondVersion));
        if (tag == null && isBlank(firstVersion) && isBlank(secondVersion))
          throw new ExploitUnsupported(
              "Combination of version not supported: " + exploit.getTitle());
      } catch (ParseException e) {
        log.warn(e.toString());
        throw new ExploitUnsupported(e);
      }

      if (tag != null) versionJoomla = tag.getName();
      else throw new ExploitUnsupported("No docker image Joomla compatible found");

      exploitDir = Utils.createDir(EXPLOITS_DIR + "/" + exploit.getId());
    } else if (exploit.getFilenameVulnApp() != null) {

      type = JoomlaType.COMPONENT;
      // Maybe a component o plugin -> check if there is a vuln app
      exploitDir = Utils.createDir(EXPLOITS_DIR + "/" + exploit.getId());

      log.info("Exploit has Vulnerable App. Downloading it");
      final var zipFile = new File(exploitDir, "/component/" + exploit.getFilenameVulnApp());
      systemCve2Docker.downloadVulnApp(exploit.getFilenameVulnApp(), zipFile);
    } else
      throw new ExploitUnsupported(
          "No related to Core and No Vulnerable App available. Cannot complete!");

    // Copy All necessary files
    copyContent(exploitDir, type, exploit.getFilenameVulnApp(), versionJoomla);
    log.info("Configuration created. Trying to configure it..");

    String[] cmdSetup =
        exploit.getFilenameVulnApp() == null
            ? new String[] {"sh", "setup.sh"}
            : new String[] {"sh", "setup.sh", exploit.getFilenameVulnApp()};
    // Setup
    ConfigurationUtils.setupConfiguration(
        exploitDir, ENDPOINT_TO_TEST, MAX_TIME_TEST, removeConfig, cmdSetup);

    log.info("Container configured correctly!");
  }

  /**
   * Find a Docker Tag that is compatible with the specific version of joomla provided
   *
   * @param version the version of Joomla
   * @return null if no tag has been found.
   * @throws IOException exception occurred during the request to dockerhub
   */
  private SearchTagVO.TagVO findTag(@NonNull Version version) throws IOException {
    // Doesn't exist a docker image before 4.0.0
    if (version.compareTo(Version.parse("3.4")) < 0) return null;

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

    if (!baseDir.isDirectory()) throw new IOException("The baseDir provided is not a directory");

    FileUtils.copyDirectory(new File(CONFIG_DIR), baseDir);

    // Copy the env file and append the component name
    var env = new File(baseDir, ".env");
    var contentEnv = readFileToString(env, StandardCharsets.UTF_8);

    //  Read Docker-compose
    final var yamlFactory = ConfigurationUtils.getYAMLFactoryDockerCompose();

    ObjectMapper om = new ObjectMapper(yamlFactory);
    final var dockerCompose =
        om.readValue(new File(baseDir, "docker-compose.yml"), DockerCompose.class);

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
}
