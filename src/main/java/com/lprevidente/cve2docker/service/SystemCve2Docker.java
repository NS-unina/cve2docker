package com.lprevidente.cve2docker.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import com.lprevidente.cve2docker.entity.pojo.*;
import com.lprevidente.cve2docker.entity.pojo.docker.DockerCompose;
import com.lprevidente.cve2docker.entity.vo.dockerhub.SearchTagVO;
import com.lprevidente.cve2docker.exception.ExploitUnsupported;
import com.lprevidente.cve2docker.utility.Utils;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.expression.ParseException;
import org.springframework.stereotype.Service;

import javax.naming.ConfigurationException;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import static com.lprevidente.cve2docker.utility.Utils.extractZip;
import static org.apache.commons.io.FileUtils.readFileToString;
import static org.apache.commons.io.FileUtils.write;
import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

@Slf4j
@Service
public class SystemCve2Docker {

  @Value("${spring.config.exploits-dir}")
  private String EXPLOITS_DIR;

  @Value("${spring.config.wordpress-dir}")
  private String WORDPRESS_DIR;

  @Value("${spring.config.joomla-dir}")
  private String JOOMLA_DIR;

  private final Long MAX_TIME_TEST;

  public SystemCve2Docker(@Value("${spring.config.max-time-test}") Integer MAX_TIME_TEST) {
    this.MAX_TIME_TEST = TimeUnit.MINUTES.toMillis(MAX_TIME_TEST);
  }

  private static final Pattern PATTERN_VERSION_EXPLOITDB =
      Pattern.compile(
          "(<(?:\\s))?(\\d(?:[.][\\d+|x]+)(?:[.][\\d|x]+)?)(\\/)?(\\d(?:[.][\\d|x]+)?(?:[.][\\d|x])?)?",
          Pattern.CASE_INSENSITIVE);

  private static final Pattern PATTERN_WORDPRESS =
      Pattern.compile(
          "WordPress(?:.*)\\s(Plugin|Theme|Core)(.*?)-(?:\\s)", Pattern.CASE_INSENSITIVE);

  private static final Pattern PATTERN_TARGET_WORDPRESS =
      Pattern.compile(
          "wordpress.org\\/(?:plugins|plugin|theme|themes)?\\/(.*?)(?:[\\.|\\/])",
          Pattern.CASE_INSENSITIVE);

  private static final Pattern PATTERN_JOOMLA =
      Pattern.compile(
          "Joomla!(?:.*)\\s(Core|Component|Plugin)(.*?)-(?:\\s)", Pattern.CASE_INSENSITIVE);

  @Autowired private NistService nistService;

  @Autowired private ExploitDBService exploitDBService;

  @Autowired private DockerHubService dockerHubService;

  @Autowired private WordpressService wordpressService;

  public void genConfigurationFromExploit(@NonNull String edbID)
      throws ExploitUnsupported, IOException, ConfigurationException {
    ExploitDB exploitDB = null;
    try {
      exploitDB = exploitDBService.getExploitDBFromSite(Long.parseLong(edbID));
    } catch (Exception ignored) {
    }

    if (Objects.isNull(exploitDB)) throw new ExploitUnsupported("Exploit doesn't exist");

    log.info("Exploit Found in ExploitDB");

    if (!(exploitDB.getType().equalsIgnoreCase("WEBAPPS")))
      throw new ExploitUnsupported("Platform not supported");

    if (StringUtils.containsIgnoreCase(exploitDB.getTitle(), "wordpress"))
      genConfigurationForWordpress(exploitDB);
    else if (StringUtils.containsIgnoreCase(exploitDB.getTitle(), "joomla"))
      genConfigurationForJoomla(exploitDB);
  }

  public void genConfigurationForWordpress(@NonNull ExploitDB exploit)
      throws ExploitUnsupported, IOException, ConfigurationException {
    log.info("Generating configuration for Wordpress Exploit");
    final var matcherWordpress = PATTERN_WORDPRESS.matcher(exploit.getTitle());

    if (!matcherWordpress.find())
      throw new ExploitUnsupported("Pattern title unknown: " + exploit.getTitle());

    // Extract from title the Type and Target (aka Product)
    var type = WordpressType.valueOf(matcherWordpress.group(1).trim().toUpperCase());
    var target = matcherWordpress.group(2).trim();

    // Extract the version from title
    final var matcher = PATTERN_VERSION_EXPLOITDB.matcher(target);
    if (!matcher.find()) throw new ExploitUnsupported("Pattern version unknown: " + target);

    // Remove the version
    String product = null;
    if (StringUtils.isNotBlank(exploit.getSoftwareLink())) {
      var targetMatcher = PATTERN_TARGET_WORDPRESS.matcher(exploit.getSoftwareLink());
      if (targetMatcher.find()) product = targetMatcher.group(1);
      else if (StringUtils.isNotBlank(exploit.getProductLink())) {
        targetMatcher = PATTERN_TARGET_WORDPRESS.matcher(exploit.getProductLink());
        if (targetMatcher.find()) product = targetMatcher.group(1);
      }
    }
    if (product == null) product = Utils.formatString(target.replace(matcher.group(), ""));

    final var less = matcher.group(1);
    final var firstVersion = matcher.group(2);
    final var slash = matcher.group(3);
    final var secondVersion = matcher.group(4);

    String versionWordpress = null;

    final var exploitDir = new File(EXPLOITS_DIR + "/" + exploit.getId());
    if (!exploitDir.exists() && !exploitDir.mkdirs())
      throw new IOException("Impossible to create folder: " + exploitDir.getPath());

    if (type == WordpressType.CORE) {
      SearchTagVO.TagVO tag;
      try {
        if (isBlank(less) && isNotBlank(firstVersion) && isBlank(slash))
          tag = findTagForWordpress(Version.parse(firstVersion));
        else if (isNotBlank(firstVersion) && isNotBlank(slash) && isNotBlank(secondVersion)) {
          // Search at first for the first version, if no tag found search for the second
          tag = findTagForWordpress(Version.parse(firstVersion));
          if (tag == null) tag = findTagForWordpress(Version.parse(secondVersion));

        } else if (isNotBlank(less) && isNotBlank(firstVersion)) {
          tag = findTagForWordpress(Version.parse(firstVersion));
          if (tag == null) {
            // TODO: sistemare
            log.info("Tag not found with version < {}", firstVersion);
          }
        } else throw new ExploitUnsupported("Combination of versions not supported");
      } catch (ParseException e) {
        log.warn(e.toString());
        throw new ExploitUnsupported(e);
      }

      if (tag != null) versionWordpress = tag.getName();
      else throw new ExploitUnsupported("No docker image of Wordpress compatible found");

    } else {
      var isCheckout = false;
      File typeDir;
      switch (type) {
        case PLUGIN:
          typeDir = new File(exploitDir, "/plugins/" + product);
          if (!typeDir.exists() && !typeDir.mkdirs())
            throw new IOException("Impossible to create folder: " + typeDir.getPath());
          isCheckout = wordpressService.checkoutPlugin(product, firstVersion, typeDir);
          break;

        case THEME:
          typeDir = new File(exploitDir, "/themes/" + product);
          if (!typeDir.exists() && !typeDir.mkdirs())
            throw new IOException("Impossible to create folder: " + typeDir.getPath());
          isCheckout = wordpressService.checkoutTheme(product, firstVersion, typeDir);
          break;

        default:
          throw new IllegalStateException("Unexpected value: " + type);
      }

      // If checkout has failed and exploit has a vuln app, download and extract it
      if (!isCheckout && exploit.getIdVulnApp() != null) {
        log.info("Exploit has vuln App. Downloading and extracting it");
        final var zipFile = new File(exploitDir, exploit.getIdVulnApp());
        exploitDBService.downloadVulnApp(exploit.getIdVulnApp(), zipFile);
        extractZip(zipFile, typeDir);
        var files = typeDir.listFiles();
        if (files != null && files.length == 1 && files[0].isDirectory())
          product += "/" + files[0].getName();
      } else if (!isCheckout)
        throw new ExploitUnsupported(type + " not found in SVN and no Vuln App exist");
    }

    // Copy the config files
    copyWordpressContent(exploitDir, type, product, versionWordpress);
    log.info("Configuration created. Testing the correctness of configuration");

    // Activate any plugin/theme and test the configuration
    testCorrectnessWordpressConfiguration(exploitDir, type, product);
    log.info("Configuration is correct");
  }

  public void genConfigurationForJoomla(@NonNull ExploitDB exploit)
      throws ExploitUnsupported, IOException, ConfigurationException {
    log.info("Generating configuration for Joomla Exploit");
    final var matcherJoomla = PATTERN_JOOMLA.matcher(exploit.getTitle());

    if (!matcherJoomla.find())
      throw new ExploitUnsupported("Pattern title unknown: " + exploit.getTitle());

    // Extract from title the Type and Target (aka Product)
    var type = JoomlaType.valueOf(matcherJoomla.group(1).trim().toUpperCase());

    if (type == JoomlaType.COMPONENT || type == JoomlaType.PLUGIN) {

      final var exploitDir = new File(EXPLOITS_DIR + "/" + exploit.getId());
      if (!exploitDir.exists() && !exploitDir.mkdirs())
        throw new IOException("Impossible to create folder: " + exploitDir.getPath());

      if (exploit.getIdVulnApp() != null) {
        log.info("Exploit has Vuln App. Downloading it");
        final var zipFile = new File(exploitDir, "/component/" + exploit.getIdVulnApp());
        exploitDBService.downloadVulnApp(exploit.getIdVulnApp(), zipFile);

        copyJoomlaContent(exploitDir, exploit.getIdVulnApp());
        testCorrectnessJoomlaConfiguration(exploitDir, exploit.getIdVulnApp());

      } else throw new ExploitUnsupported("No VulnApp available. Cannot complete");
    } else throw new ExploitUnsupported("Joomla Type Core Not Supported");
  }

  private SearchTagVO.TagVO findTagForWordpress(Version version) throws IOException {
    final var cpe = new CPE("2.3", CPE.Part.APPLICATION, "wordpress", "wordpress", version);

    // Return all CPE that match the previous
    final var cpes = nistService.getCpes(cpe);
    if (cpes == null || cpes.getResult().getCpes().isEmpty()) return null;

    SearchTagVO.TagVO tag = null;

    //  Cycle through all CPE until find a tag on dockerhub corresponding to the version
    final var iterator = cpes.getResult().getCpes().iterator();
    while (iterator.hasNext() && tag == null) {
      var cpeMatchVO = iterator.next();
      final var tags =
          dockerHubService.searchTags(
              cpe.getProduct(), cpeMatchVO.getCpe().getVersion().toString());

      // Search for a tag with the exact name of the version
      tag =
          tags.stream()
              .filter(
                  _t ->
                      cpeMatchVO.getCpe().getVersion().getPattern().matcher(_t.getName()).matches())
              .findFirst()
              .orElse(null);

      // If not found, finding the FIRST repo with the containing name of the version
      if (tag == null)
        tag =
            tags.stream()
                .filter(
                    _t ->
                        cpeMatchVO.getCpe().getVersion().getPattern().matcher(_t.getName()).find())
                .findFirst()
                .orElse(null);

      if (tag != null && tag.getName().contains("cli")) tag = null;
    }
    return tag;
  }

  private void copyWordpressContent(
      @NonNull File baseDir, @NonNull WordpressType type, @NonNull String product, String version)
      throws IOException {

    FileUtils.copyDirectory(new File(WORDPRESS_DIR), baseDir);

    // Copy the env file and append the plugin or theme name
    var env = new File(baseDir, ".env");
    var contentEnv = readFileToString(env, StandardCharsets.UTF_8);

    //  Read Docker-compose
    final var yamlFactory =
        new YAMLFactory()
            .configure(YAMLGenerator.Feature.INDENT_ARRAYS_WITH_INDICATOR, true)
            .configure(YAMLGenerator.Feature.ALWAYS_QUOTE_NUMBERS_AS_STRINGS, true)
            .configure(YAMLGenerator.Feature.MINIMIZE_QUOTES, true)
            .configure(YAMLGenerator.Feature.INDENT_ARRAYS, true)
            .configure(YAMLGenerator.Feature.WRITE_DOC_START_MARKER, false);

    ObjectMapper om = new ObjectMapper(yamlFactory);
    final var dockerCompose =
        om.readValue(new File(baseDir, "docker-compose.yml"), DockerCompose.class);

    switch (type) {
      case CORE:
        contentEnv = contentEnv.replace("latest", version);
        break;
      case PLUGIN:
        contentEnv += "\nPLUGIN_NAME=" + product;
        dockerCompose
            .getServices()
            .get("wp")
            .getVolumes()
            .add("./plugins/${PLUGIN_NAME}/:/var/www/html/wp-content/plugins/${PLUGIN_NAME}");
        dockerCompose
            .getServices()
            .get("wpcli")
            .getVolumes()
            .add("./plugins/${PLUGIN_NAME}/:/var/www/html/wp-content/plugins/${PLUGIN_NAME}");
        break;
      case THEME:
        contentEnv += "\nTHEME_NAME=" + product;
        dockerCompose
            .getServices()
            .get("wp")
            .getVolumes()
            .add("./themes/${THEME_NAME}/:/var/www/html/wp-content/themes/${THEME_NAME}");
        dockerCompose
            .getServices()
            .get("wpcli")
            .getVolumes()
            .add("./themes/${THEME_NAME}/:/var/www/html/wp-content/themes/${THEME_NAME}");
        break;
    }

    write(env, contentEnv, StandardCharsets.UTF_8);
    om.writeValue(new File(baseDir, "docker-compose.yml"), dockerCompose);
  }

  public void copyJoomlaContent(@NonNull File baseDir, @NonNull String product) throws IOException {

    FileUtils.copyDirectory(new File(JOOMLA_DIR), baseDir);
    // Copy the env file and append the plugin or theme name
    var env = new File(baseDir, ".env");
    var contentEnv = readFileToString(env, StandardCharsets.UTF_8);

    contentEnv += "\nCOMPONENT_NAME=" + product;

    write(env, contentEnv, StandardCharsets.UTF_8);
  }

  public void testCorrectnessWordpressConfiguration(
      File exploitDir, WordpressType type, String product) throws ConfigurationException {
    try {
      var res = Utils.executeProgram(exploitDir, "sh", "start.sh");
      if (!res.equals("ok")) throw new ConfigurationException("Impossible to start docker: " + res);

      final long start = System.currentTimeMillis();
      final var client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
      final var request =
          HttpRequest.newBuilder(new URI("http://localhost/wp-admin/install.php")).GET().build();

      // I try to setup wordpress in a maximum time
      var setupCompleted = false;
      while ((System.currentTimeMillis() - start) <= MAX_TIME_TEST && !setupCompleted) {
        try {
          var response = client.send(request, HttpResponse.BodyHandlers.ofString());
          if (response.statusCode() == 200) {
            res =
                Utils.executeProgram(
                    exploitDir, "sh", "setup.sh", type.name().toLowerCase(), product);
            if (res.equals("ok")) setupCompleted = true;
            else throw new ConfigurationException("Impossible to start docker: " + res);
          }
        } catch (IOException ignore) {
        }
      }

      // If time used to test exceeded MAX value means there might be some problem
      if (!setupCompleted)
        throw new ConfigurationException(
            "Exceeded the maximum time to test. Maybe te configuration is not correct");
    } catch (IOException | InterruptedException | URISyntaxException e) {
      e.printStackTrace();
      throw new ConfigurationException("Impossible to test configuration: " + e.getMessage());
    } finally {
      // Stop container
      try {
        Utils.executeProgram(exploitDir, "docker-compose", "stop");
      } catch (Exception ignored) {
      }
    }
  }

  public void testCorrectnessJoomlaConfiguration(File exploitDir, String product)
      throws ConfigurationException {
    try {
      var res = Utils.executeProgram(exploitDir, "sh", "start.sh");
      if (!res.equals("ok")) throw new ConfigurationException("Impossible to start docker: " + res);

      final long start = System.currentTimeMillis();
      final var client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
      final var request =
          HttpRequest.newBuilder(new URI("http://localhost/installation/index.php")).GET().build();

      // I try to setup wordpress in a maximum time
      var setupCompleted = false;
      while ((System.currentTimeMillis() - start) <= MAX_TIME_TEST && !setupCompleted) {
        try {
          var response = client.send(request, HttpResponse.BodyHandlers.ofString());
          if (response.statusCode() == 200) {
            res = Utils.executeProgram(exploitDir, "sh", "setup.sh", product);
            if (res.equals("ok")) setupCompleted = true;
            else throw new ConfigurationException("Impossible to start docker: " + res);
          }
        } catch (IOException ignore) {
        }
      }

      // If time used to test exceeded MAX value means there might be some problem
      if (!setupCompleted)
        throw new ConfigurationException(
            "Exceeded the maximum time to test. Maybe te configuration is not correct");
    } catch (IOException | InterruptedException | URISyntaxException e) {
      e.printStackTrace();
      throw new ConfigurationException("Impossible to test configuration: " + e.getMessage());
    } finally {
      // Stop container
      try {
        Utils.executeProgram(exploitDir, "docker-compose", "stop");
      } catch (Exception ignored) {
      }
    }
  }
}
