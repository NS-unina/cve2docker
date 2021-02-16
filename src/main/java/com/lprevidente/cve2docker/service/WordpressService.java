package com.lprevidente.cve2docker.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import com.lprevidente.cve2docker.entity.pojo.CPE;
import com.lprevidente.cve2docker.entity.pojo.ExploitDB;
import com.lprevidente.cve2docker.entity.pojo.Version;
import com.lprevidente.cve2docker.entity.pojo.WordpressType;
import com.lprevidente.cve2docker.entity.pojo.docker.DockerCompose;
import com.lprevidente.cve2docker.entity.vo.dockerhub.SearchTagVO;
import com.lprevidente.cve2docker.exception.ExploitUnsupported;
import com.lprevidente.cve2docker.utility.ConfigurationUtils;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
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

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import static com.lprevidente.cve2docker.utility.Utils.extractZip;
import static com.lprevidente.cve2docker.utility.Utils.formatString;
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

  @SneakyThrows
  public void genConfiguration(@NonNull ExploitDB exploit, boolean removeConfig) {
    log.info("Generating configuration for Wordpress Exploit");
    final var matcherWordpress = PATTERN_WORDPRESS.matcher(exploit.getTitle());

    if (!matcherWordpress.find())
      throw new ExploitUnsupported("Pattern title unknown: " + exploit.getTitle());

    // Extract from title the Type and Target (aka Product)
    var type = WordpressType.valueOf(matcherWordpress.group(1).trim().toUpperCase());
    var target = matcherWordpress.group(2).trim();

    // Extract the version from title
    final var matcher = PATTERN_VERSION.matcher(target);
    if (!matcher.find()) throw new ExploitUnsupported("Version not present or pattern unkown: " + target);

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

    final var exploitDir = new File(EXPLOITS_DIR + "/" + exploit.getId());
    if (!exploitDir.exists() && !exploitDir.mkdirs())
      throw new IOException("Impossible to create folder: " + exploitDir.getPath());

    // Extract the main version
    final var firstVersion = matcher.group(2);

    if (type == WordpressType.CORE) {
      // Extract the different type of version
      final var less = matcher.group(1);
      final var slash = matcher.group(3);
      final var secondVersion = matcher.group(4);
      SearchTagVO.TagVO tag;

      try {
        if (isBlank(less) && isNotBlank(firstVersion) && isBlank(slash))
          tag = findTag(Version.parse(firstVersion));
        else if (isNotBlank(firstVersion) && isNotBlank(slash) && isNotBlank(secondVersion)) {
          // Search at first for the first version, if no tag found search for the second
          tag = findTag(Version.parse(firstVersion));
          if (tag == null) tag = findTag(Version.parse(secondVersion));

        } else if (isNotBlank(less) && isNotBlank(firstVersion)) {
          tag = findTag(Version.parse(firstVersion));
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
      else throw new ExploitUnsupported("No docker image Wordpress compatible found");

    } else {
      var isCheckout = false;
      File typeDir;

      switch (type) {
        case PLUGIN:
          typeDir = new File(exploitDir, "/plugins/" + product);
          if (!typeDir.exists() && !typeDir.mkdirs())
            throw new IOException("Impossible to create folder: " + typeDir.getPath());
          isCheckout = checkoutPlugin(product, firstVersion, typeDir);
          break;

        case THEME:
          typeDir = new File(exploitDir, "/themes/" + product);
          if (!typeDir.exists() && !typeDir.mkdirs())
            throw new IOException("Impossible to create folder: " + typeDir.getPath());
          isCheckout = checkoutTheme(product, firstVersion, typeDir);
          break;

        default:
          throw new IllegalStateException("Unexpected value: " + type);
      }

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
            log.debug("Download completed");
            downloaded = true;
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

  private SearchTagVO.TagVO findTag(Version version) throws IOException {
    final var cpe = new CPE("2.3", CPE.Part.APPLICATION, "wordpress", "wordpress", version);

    // Return all CPE that match the previous
    final var cpes = systemCve2Docker.getCpes(cpe);
    if (cpes == null || cpes.getResult().getCpes().isEmpty()) return null;

    SearchTagVO.TagVO tag = null;

    //  Cycle through all CPE until find a tag on dockerhub corresponding to the version
    final var iterator = cpes.getResult().getCpes().iterator();
    while (iterator.hasNext() && tag == null) {
      var cpeMatchVO = iterator.next();
      final var tags =
          systemCve2Docker.searchTags(
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

  private void copyContent(
      @NonNull File baseDir, @NonNull WordpressType type, @NonNull String product, String version)
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

  private SVNClientManager getSVNClientManager() throws SVNException {
    ISVNOptions myOptions = SVNWCUtil.createDefaultOptions(true);
    ISVNAuthenticationManager myAuthManager = SVNWCUtil.createDefaultAuthenticationManager();
    return SVNClientManager.newInstance(myOptions, myAuthManager);
  }

  public boolean checkoutPlugin(String pluginName, String version, File destDir) {
    try {
      log.debug(
          "[checkoutPlugin] Request checkout - pluginName = {}  version = {}", pluginName, version);
      final var updateClient = getSVNClientManager().getUpdateClient();
      updateClient.doCheckout(
          SVNURL.parseURIEncoded(
              "https://plugins.svn.wordpress.org/" + pluginName + "/tags/" + version),
          destDir,
          SVNRevision.HEAD,
          SVNRevision.HEAD,
          SVNDepth.INFINITY,
          true);
      log.debug("[checkoutPlugin] Checkout completed");
      return true;
    } catch (SVNException e) {
      log.warn("[checkoutPlugin] Unable to checkout: " + e.getMessage());
      return false;
    }
  }

  public boolean checkoutTheme(String themeName, String version, File destDir) {
    try {
      log.debug(
          "[checkoutTheme] Request checkout - pluginName = {}  version = {}", themeName, version);
      final var updateClient = getSVNClientManager().getUpdateClient();
      updateClient.doCheckout(
          SVNURL.parseURIEncoded("https://themes.svn.wordpress.org/" + themeName + "/" + version),
          destDir,
          SVNRevision.HEAD,
          SVNRevision.HEAD,
          SVNDepth.INFINITY,
          true);
      log.debug("[checkoutPlugin] Checkout completed");
      return true;
    } catch (SVNException e) {
      log.warn("[checkoutTheme] Unable to checkout: " + e.getMessage());
      return false;
    }
  }
}
