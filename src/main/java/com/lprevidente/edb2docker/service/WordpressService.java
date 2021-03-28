package com.lprevidente.edb2docker.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lprevidente.edb2docker.entity.pojo.*;
import com.lprevidente.edb2docker.entity.pojo.docker.DockerCompose;
import com.lprevidente.edb2docker.entity.vo.dockerhub.SearchTagVO;
import com.lprevidente.edb2docker.exception.*;
import com.lprevidente.edb2docker.utility.ConfigurationUtils;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.tmatesoft.svn.core.SVNDepth;
import org.tmatesoft.svn.core.SVNException;
import org.tmatesoft.svn.core.SVNURL;
import org.tmatesoft.svn.core.auth.ISVNAuthenticationManager;
import org.tmatesoft.svn.core.wc.ISVNOptions;
import org.tmatesoft.svn.core.wc.SVNClientManager;
import org.tmatesoft.svn.core.wc.SVNRevision;
import org.tmatesoft.svn.core.wc.SVNWCUtil;

import java.io.File;
import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import static com.lprevidente.edb2docker.entity.pojo.JoomlaType.CORE;
import static com.lprevidente.edb2docker.utility.Utils.isNotEmpty;
import static com.lprevidente.edb2docker.utility.Utils.*;
import static org.apache.commons.lang3.StringUtils.*;

@Service
@Slf4j
public class WordpressService implements IGenerateService {

  @Autowired @Lazy private SystemCve2Docker systemCve2Docker;

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

  private static final Pattern PATTERN_VERSION =
      Pattern.compile(
          "(<(?:\\s))?(\\d(?:[.][\\d+|x]+)(?:[.][\\d|x]+)?)(/)?(\\d(?:[.][\\d|x]+)?(?:[.][\\d|x])?)?",
          Pattern.CASE_INSENSITIVE);

  private static final Pattern PATTERN_WORDPRESS =
      Pattern.compile(
          "WordPress(?:.*)\\s(Plugin|Theme|Core)(.*?)-(?:\\s)", Pattern.CASE_INSENSITIVE);

  private static final Pattern PATTERN_TARGET_WORDPRESS =
      Pattern.compile(
          "wordpress.org(?:.*?)/(?:plugins|plugin|theme|themes)?/(.*?)(?:[.|/])",
          Pattern.CASE_INSENSITIVE);

  private static final String[] filenames = new String[] {"start.sh", "setup.sh"};

  private final Long MAX_TIME_TEST;

  public WordpressService(
      @Value("${spring.config.wordpress.max-time-test}") Integer MAX_TIME_TEST) {
    this.MAX_TIME_TEST = TimeUnit.MINUTES.toMillis(MAX_TIME_TEST);
  }

  @Override
  public boolean canHandle(@NonNull ExploitDB exploitDB) {
    return containsIgnoreCase(exploitDB.getTitle(), ExploitType.WORDPRESS.name())
        && !containsIgnoreCase(exploitDB.getTitle(), ExploitType.JOOMLA.name());
  }

  /**
   * Method to generate configuration for the exploit related to <b>Wordpress</b>. The configuration
   * consist in docker-compose, env file e other files depending on the exploit type.
   *
   * <p>The configuration is saved in ./content/generated/{edbID} folder.
   *
   * @param exploit not null
   * @param removeConfig if true the configuration will be removed after it has been setup.
   * @throws ParseExploitException throws when it is not possible to extrapolate the type or version
   *     of the exploit
   * @throws ImageNotFoundException throws when there is no image related to wordpress core
   * @throws NoVulnerableAppException throws when there isn't a vulnerable app for the exploit
   * @throws ExploitUnsupported throws when there is no possibility to generate the configuration.
   * @throws ConfigurationException throws when there is a problem during the setup or test of the
   *     configuration.
   */
  @Override
  public void genConfiguration(@NonNull ExploitDB exploit, boolean removeConfig)
      throws GenerationException {
    log.info("Generating configuration for Wordpress Exploit");
    final var matcherWordpress = PATTERN_WORDPRESS.matcher(exploit.getTitle());

    if (!matcherWordpress.find())
      throw new ParseExploitException("Pattern title unknown: " + exploit.getTitle());

    // Extract from title the Type and Target (aka Product)
    var type = WordpressType.valueOf(matcherWordpress.group(1).trim().toUpperCase());
    var target = matcherWordpress.group(2).trim();

    // Extract the version from title
    var matcher = PATTERN_VERSION.matcher(target);
    final String firstVersion;
    final String secondVersion;
    String entireVersion = "";

    var find = matcher.find();
    if (!find && isNotBlank(exploit.getVersion())) {
      // Extract the version from Version in PoC
      matcher = PATTERN_VERSION.matcher(exploit.getVersion());
      find = matcher.find();
    }

    if (find) { // If there is a pattern version
      entireVersion = matcher.group();
      firstVersion = matcher.group(2);
      secondVersion = matcher.group(4);
    } else if (type != WordpressType.CORE
        && isNotBlank(exploit.getFilenameVulnApp())) { // There is a vulnerable app for plugin/theme
      firstVersion = null;
      secondVersion = null;
    } else throw new ParseExploitException("Version unknown and No vulnerable App is present");

    String toAdd = null;

    // Trying to extract the name of plugin/theme from software link or toAdd link
    // if they are related to wordpress.org
    if (isNotBlank(exploit.getSoftwareLink())) {
      var targetMatcher = PATTERN_TARGET_WORDPRESS.matcher(exploit.getSoftwareLink());
      if (targetMatcher.find()) toAdd = targetMatcher.group(1);
      else if (isNotBlank(exploit.getProductLink())) {
        targetMatcher = PATTERN_TARGET_WORDPRESS.matcher(exploit.getProductLink());
        if (targetMatcher.find()) toAdd = targetMatcher.group(1);
      }
    }

    // If the toAdd hasn't been found in the links, extract it from title removing the version and
    // extracting
    if (toAdd == null) toAdd = formatString(remove(target, entireVersion));

    File exploitDir = null;
    try {
      exploitDir = createDir(EXPLOITS_DIR + "/" + exploit.getId());

      if (type == WordpressType.CORE) { // Find the correct image for wordpress
        SearchTagVO.TagVO tag = null;

        // Search a WordPress image with a version equal to the first Version
        if (isNotBlank(firstVersion)) tag = findTag(Version.parse(firstVersion));

        // If no tag has been found, then search with the second Version
        if (tag == null && isNotBlank(secondVersion)) tag = findTag(Version.parse(secondVersion));

        // If no tag has been found and there is no first and second version, throw an error.
        if (tag == null && isBlank(firstVersion) && isBlank(secondVersion))
          throw new ParseExploitException("No version found in " + entireVersion);

        if (tag != null) toAdd = tag.getName();
        else throw new ImageNotFoundException("Wordpress");

      } else { // Find the Plugin/Theme associated with

        File typeDir = new File(exploitDir, type.name().toLowerCase() + "s/" + toAdd);
        if (!typeDir.exists() && !typeDir.mkdirs())
          throw new IOException("Impossible to create the folder in " + typeDir.getPath());

        var isCheckout = false;
        if (isNotBlank(firstVersion)) isCheckout = checkout(type, toAdd, firstVersion, typeDir);

        // If checkout failed try with software link if exist
        if (!isCheckout) {
          var downloaded = false;
          File zipFile = null;

          // Try to download the zip file from software link
          if (isNotBlank(exploit.getSoftwareLink())
              && contains(exploit.getSoftwareLink(), toAdd)
              && isNotBlank(firstVersion)
              && contains(exploit.getSoftwareLink(), firstVersion)) {

            log.info("Trying to download from Software link: {}", exploit.getSoftwareLink());

            zipFile = new File(exploitDir, toAdd + ".zip");
            try {
              // subs
              copyURLToFile(exploit.getSoftwareLink(), zipFile);
              downloaded = isNotEmpty(zipFile);
              if (downloaded) log.info("Download completed");
              else log.warn("Zip file is empty or corrupted");
            } catch (Exception e) {
              log.warn(
                  "An error occurred during the download form Software Link: {}",
                  exploit.getSoftwareLink());
            }
          }

          // Try to download the vulnerable app if there is
          if (!downloaded && StringUtils.isNotBlank(exploit.getFilenameVulnApp())) {
            zipFile = new File(exploitDir, exploit.getFilenameVulnApp());
            try {
              log.info("Trying to download from ExploitDB");
              systemCve2Docker.downloadVulnApp(exploit.getFilenameVulnApp(), zipFile);
              downloaded = isNotEmpty(zipFile);
              if (downloaded) log.info("Download completed");
              else log.warn("Zip file is empty or corrupted");
            } catch (IOException e) {
              log.warn("An error occurred during the download from ExploitDB");
            }
          }

          if (downloaded) {
            decompress(zipFile, typeDir);
            var files = typeDir.listFiles();
            if (files != null && files.length == 1 && files[0].isDirectory()) {
              FileUtils.copyDirectory(files[0], typeDir);
              FileUtils.deleteDirectory(files[0]);
            }
          } else throw new NoVulnerableAppException();
        }
      }

      // Copy the config files
      copyContent(exploitDir, type, toAdd);
      log.info("Configuration created. Trying to configure it");

      String[] cmdSetup =
          type == WordpressType.CORE
              ? new String[] {"sh", "setup.sh"}
              : new String[] {"sh", "setup.sh", type.name().toLowerCase(), toAdd};

      // Activate any plugin/theme and test the configuration
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
      throw new GenerationException("An IO Exception occurred : " + e.getMessage());
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
   * Find a Docker Tag that is compatibile with the specific version of wordpress provided
   *
   * @param version the version of wordpress
   * @return null if no tag has been found.
   * @throws IOException exception occurred during the request to dockerhub
   */
  private SearchTagVO.TagVO findTag(@NonNull Version version) throws IOException {
    // Doesn't exist a docker image before 4.1.0
    if (version.compareTo(Version.parse("4.1.0")) < 0) return null;

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
   * @param toAdd the value to add to docker-compose. If type is Core, represent the version,
   *     otherwise the theme or plugin name.
   * @throws IOException if the file provided is not a directory or an error during the copy
   *     process.
   */
  private void copyContent(@NonNull File baseDir, @NonNull WordpressType type, String toAdd)
      throws IOException {

    // FileUtils.copyDirectory(new File(CONFIG_DIR), baseDir);
    ConfigurationUtils.copyFiles(CONFIG_DIR, baseDir, filenames);

    //  Read Docker-compose
    final var yamlFactory = ConfigurationUtils.getYAMLFactoryDockerCompose();

    ObjectMapper om = new ObjectMapper(yamlFactory);
    final var dockerCompose =
        om.readValue(
            ConfigurationUtils.getBufferedReaderResource(CONFIG_DIR + "/docker-compose.yml"),
            DockerCompose.class);

    switch (type) {
      case CORE:
        dockerCompose.getServices().get("wp").setImage("wordpress:" + toAdd);
        break;
      case THEME:
      case PLUGIN:
        String volume =
            String.format(
                "./%ss/%s/:/var/www/html/wp-content/%ss/%s",
                type.name().toLowerCase(), toAdd, type.name().toLowerCase(), toAdd);
        dockerCompose.getServices().get("wp").getVolumes().add(volume);
        dockerCompose.getServices().get("wpcli").getVolumes().add(volume);
        break;
    }

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

  /**
   * Clean the exploit directory deleting all unnecessary files
   *
   * @param exploitDir not null
   */
  public void cleanDirectory(@NonNull File exploitDir) {
    try {
      // Remove files
      FileUtils.forceDelete(new File(exploitDir, "setup.sh"));
      FileUtils.forceDelete(new File(exploitDir, "start.sh"));
    } catch (IOException ignored) {
    }
  }
}
