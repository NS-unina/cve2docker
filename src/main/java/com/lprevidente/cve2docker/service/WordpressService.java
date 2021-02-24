package com.lprevidente.cve2docker.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lprevidente.cve2docker.entity.pojo.CPE;
import com.lprevidente.cve2docker.entity.pojo.ExploitDB;
import com.lprevidente.cve2docker.entity.pojo.Version;
import com.lprevidente.cve2docker.entity.pojo.WordpressType;
import com.lprevidente.cve2docker.entity.pojo.docker.DockerCompose;
import com.lprevidente.cve2docker.entity.vo.dockerhub.SearchTagVO;
import com.lprevidente.cve2docker.exception.ConfigurationException;
import com.lprevidente.cve2docker.exception.ExploitUnsupported;
import com.lprevidente.cve2docker.utility.ConfigurationUtils;
import com.lprevidente.cve2docker.utility.Utils;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.expression.ParseException;
import org.springframework.stereotype.Service;
import org.tmatesoft.svn.core.SVNDepth;
import org.tmatesoft.svn.core.SVNException;
import org.tmatesoft.svn.core.SVNURL;
import org.tmatesoft.svn.core.auth.ISVNAuthenticationManager;
import org.tmatesoft.svn.core.wc.ISVNOptions;
import org.tmatesoft.svn.core.wc.SVNClientManager;
import org.tmatesoft.svn.core.wc.SVNRevision;
import org.tmatesoft.svn.core.wc.SVNWCUtil;

import javax.annotation.PostConstruct;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import static com.lprevidente.cve2docker.utility.Utils.*;
import static org.apache.commons.io.FileUtils.readFileToString;
import static org.apache.commons.io.FileUtils.write;
import static org.apache.commons.lang3.StringUtils.*;

@Service
@Slf4j
public class WordpressService {

  @Value("${spring.config.exploits-dir}")
  private String EXPLOITS_DIR;

  @Value("${spring.config.wordpress.config-dir}")
  private String CONFIG_DIR;

  @Value("${spring.config.wordpress.endpoint-to-test}")
  private String ENDPOINT_TO_TEST;

  @Value("${spring.config.wordpress.svn-base-url.plugin}")
  private String BASE_URL_SVN_PLUGIN;

  @Value("${spring.config.wordpress.svn-base-url.theme}")
  private String BASE_URL_SVN_THEME;

  private final Long MAX_TIME_TEST;

  @Autowired private SystemCve2Docker systemCve2Docker;

  public WordpressService(
      @Value("${spring.config.wordpress.max-time-test}") Integer MAX_TIME_TEST) {
    this.MAX_TIME_TEST = TimeUnit.MINUTES.toMillis(MAX_TIME_TEST);
  }

  private static final Pattern PATTERN_VERSION =
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

  @PostConstruct
  public void checkConfig() throws BeanCreationException {
    var dir = new File(CONFIG_DIR);
    if (!dir.exists() || !dir.isDirectory())
      throw new BeanCreationException("No wordpress config dir present in " + CONFIG_DIR);

    var filenames =
        new String[] {"docker-compose.yml", "start.sh", "setup.sh", ".env", "config/php.conf.ini"};

    for (var filename : filenames) {
      var file = new File(dir, filename);
      if (!file.exists())
        throw new BeanCreationException("No " + file.getName() + " present in " + CONFIG_DIR);
    }
  }

  /**
   * Method to generate configuration for the exploit related to <b>Wordpress</b>. The configuration
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
    log.info("Generating configuration for Wordpress Exploit");
    final var matcherWordpress = PATTERN_WORDPRESS.matcher(exploit.getTitle());

    if (!matcherWordpress.find())
      throw new ExploitUnsupported("Pattern title unknown: " + exploit.getTitle());

    // Extract from title the Type and Target (aka Product)
    var type = WordpressType.valueOf(matcherWordpress.group(1).trim().toUpperCase());
    var target = matcherWordpress.group(2).trim();

    // Extract the version from title
    final var matcher = PATTERN_VERSION.matcher(target);
    if (!matcher.find())
      throw new ExploitUnsupported("Version not present or pattern unkown: " + target);

    String product = null;
    if (isNotBlank(exploit.getSoftwareLink())) {
      var targetMatcher = PATTERN_TARGET_WORDPRESS.matcher(exploit.getSoftwareLink());
      if (targetMatcher.find()) product = targetMatcher.group(1);
      else if (isNotBlank(exploit.getProductLink())) {
        targetMatcher = PATTERN_TARGET_WORDPRESS.matcher(exploit.getProductLink());
        if (targetMatcher.find()) product = targetMatcher.group(1);
      }
    }
    // Remove the version
    if (product == null) product = formatString(target.replace(matcher.group(), ""));

    String versionWordpress = null;

    final var exploitDir = createDir(EXPLOITS_DIR + "/" + exploit.getId());

    // Extract the main version
    final var firstVersion = matcher.group(2);

    if (type == WordpressType.CORE) {
      // Extract the different type of version
      // final var less = matcher.group(1);
      // final var slash = matcher.group(3);
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

      if (tag != null) versionWordpress = tag.getName();
      else throw new ExploitUnsupported("No docker image Wordpress compatible found");

    } else {
      File typeDir;

      typeDir = new File(exploitDir, "/" + type.name().toLowerCase() + "s/" + product);
      if (!typeDir.exists() && !typeDir.mkdirs())
        throw new IOException("Impossible to create folder: " + typeDir.getPath());
      var isCheckout = checkout(type, product, firstVersion, typeDir);

      // if checkout is failed try with software link if exist
      if (!isCheckout) {
        var downloaded = false;
        File zipFile = null;

        // Try to download the zip file from software link
        if (isNotBlank(exploit.getSoftwareLink())
            && contains(exploit.getSoftwareLink(), product)
            && contains(exploit.getSoftwareLink(), firstVersion)) {

          log.debug("Trying to download it from Software link...");
          zipFile = new File(exploitDir, product + ".zip");
          try {
            FileUtils.copyURLToFile(new URL(exploit.getSoftwareLink()), zipFile);
            downloaded = Utils.isNotEmpty(zipFile);
            if(downloaded)
              log.debug("Download completed");
            else
              log.warn("Zip file empty or corrupted");
          } catch (IOException e) {
            log.warn("Error during downloading from software link");
          }
        }

        // Try to download the vulnerable app if there is
        if (!downloaded && StringUtils.isNotBlank(exploit.getFilenameVulnApp())) {
          zipFile = new File(exploitDir, exploit.getFilenameVulnApp());
          try {
            log.debug("Trying to download it from Exploit-DB");
            systemCve2Docker.downloadVulnApp(exploit.getFilenameVulnApp(), zipFile);
            log.debug("Download completed");
            downloaded = true;
          } catch (IOException e) {
            log.warn("Error during downloading from Exploit-DB");
          }
        }

        if (downloaded) {
          extractZip(zipFile, typeDir);
          var files = typeDir.listFiles();
          if (files != null && files.length == 1 && files[0].isDirectory()) {
            FileUtils.copyDirectory(files[0], typeDir);
            FileUtils.deleteDirectory(files[0]);
          }
        } else {
          throw new ExploitUnsupported(type + " not found in SVN and no Vulnerable App exist");
        }
      }
    }

    // Copy the config files
    copyContent(exploitDir, type, product, versionWordpress);
    log.info("Configuration created. Trying to configure it");

    // Activate any plugin/theme and test the configuration
    ConfigurationUtils.setupConfiguration(
        exploitDir,
        ENDPOINT_TO_TEST,
        MAX_TIME_TEST,
        removeConfig,
        "sh",
        "setup.sh",
        type.name().toLowerCase(),
        product);

    // setupConfiguration(exploitDir, type, product);
    log.info("Container configured correctly!");
  }

  /**
   * Find a Docker Tag that is compatibile with the specific version of wordpress provided
   *
   * @param version the version of wordpress
   * @return null if no tag has been found.
   * @throws IOException exception occurred during the request to dockerhub
   */
  private SearchTagVO.TagVO findTag(@NonNull Version version) throws IOException {
    // Doesn't exist a docker image before 4.0.0
    if (version.compareTo(Version.parse("4.0.0")) < 0) return null;

    final var cpe = new CPE("2.3", CPE.Part.APPLICATION, "wordpress", "wordpress", version);

    return systemCve2Docker.findTag(
        cpe,
        (_t, cpeMatchVO) ->
            cpeMatchVO.getCpe().getVersion().getPattern().matcher(_t.getName()).matches(),
        (_t, cpeMatchVO) ->
            cpeMatchVO.getCpe().getVersion().getPattern().matcher(_t.getName()).find()
                && !_t.getName().contains(("cli")));
  }

  /**
   * Copy the content from the configuration directory into the directory provided. Also modifies
   * the <i>env</i> file inserting the name of plugin/theme or the version of wordpress which is
   * related the exploit.
   *
   * @param baseDir the directory in which the files should be copied. component the name of Joomla
   *     component.
   * @param type the type of wordpress exploit
   * @param product the name of the product, can be null.
   * @param version the wordpress version (/tag), should be specified only if the type is CORE.
   * @throws IOException if the file provided is not a directory or an error during the copy
   *     process.
   */
  private void copyContent(
      @NonNull File baseDir, @NonNull WordpressType type, String product, String version)
      throws IOException {

    FileUtils.copyDirectory(new File(CONFIG_DIR), baseDir);

    // Copy the env file and append the plugin or theme name
    var env = new File(baseDir, ".env");
    var contentEnv = readFileToString(env, StandardCharsets.UTF_8);

    //  Read Docker-compose
    final var yamlFactory = ConfigurationUtils.getYAMLFactoryDockerCompose();

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

  /**
   * Buld a SVNClient Manager with no particula authentication.
   *
   * @return the client manager
   */
  private SVNClientManager getSVNClientManager() {
    ISVNOptions myOptions = SVNWCUtil.createDefaultOptions(true);
    ISVNAuthenticationManager myAuthManager = SVNWCUtil.createDefaultAuthenticationManager();
    return SVNClientManager.newInstance(myOptions, myAuthManager);
  }

  /**
   * Do the checkout for the plugin or theme of the project from Wordpress official SVN.
   *
   * @param type Plugin or Theme, otherwise the result is always false.
   * @param repoName the name of the repo
   * @param version the version
   * @param destDir the directory in which the checkout should be done
   * @return true if the checkout was successful, false otherwise.
   */
  private boolean checkout(
      @NonNull WordpressType type,
      @NonNull String repoName,
      @NonNull String version,
      @NonNull File destDir) {
    try {
      String url;
      if (type.equals(WordpressType.PLUGIN))
        url = BASE_URL_SVN_PLUGIN + repoName + "/tags/" + version;
      else if (type.equals(WordpressType.THEME))
        url = BASE_URL_SVN_THEME + repoName + "/tags/" + version;
      else return false;

      log.debug(
          "[checkout] Request checkout - type = {}  repo = {}  version = {}",
          type.name(),
          repoName,
          version);

      final var updateClient = getSVNClientManager().getUpdateClient();
      updateClient.doCheckout(
          SVNURL.parseURIEncoded(url),
          destDir,
          SVNRevision.HEAD,
          SVNRevision.HEAD,
          SVNDepth.INFINITY,
          true);
      log.debug("[checkout] Checkout completed");
      return true;
    } catch (SVNException e) {
      log.warn("[checkout] Unable to checkout: " + e.getMessage());
      return false;
    }
  }
}
