package com.lprevidente.cve2docker.service;

import com.lprevidente.cve2docker.entity.pojo.CPE;
import com.lprevidente.cve2docker.entity.pojo.ExploitDB;
import com.lprevidente.cve2docker.entity.pojo.Version;
import com.lprevidente.cve2docker.entity.pojo.WordpressType;
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
import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.regex.Pattern;

import static com.lprevidente.cve2docker.utility.Utils.extractZip;
import static org.apache.commons.io.FileUtils.*;
import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

@Slf4j
@Service
public class SystemCve2Docker {

  @Value("${spring.config.exploits-dir}")
  private String BASE_DIR;

  @Value("${spring.config.wordpress-dir}")
  private String WORDPRESS_DIR;

  private static final Pattern PATTERN_VERSION_EXPLOITDB =
      Pattern.compile(
          "(<(?:\\s))?(\\d(?:[.][\\d+|x]+)(?:[.][\\d|x]+)?)(\\/)?(\\d(?:[.][\\d|x]+)?(?:[.][\\d|x])?)?",
          Pattern.CASE_INSENSITIVE);

  private static final Pattern PATTERN_WORDPRESS =
      Pattern.compile(
          "WordPress(?:.*)\\s(Plugin|Theme|Core)(.*?)-(?:\\s)", Pattern.CASE_INSENSITIVE);

  @Autowired private NistService nistService;

  @Autowired private ExploitDBService exploitDBService;

  @Autowired private DockerHubService dockerHubService;

  @Autowired private WordpressService wordpressService;

  public void genConfigurationFromExploit(@NonNull String edbID)
      throws ExploitUnsupported, IOException {
    ExploitDB exploitDB = null;
    try {
      exploitDB = exploitDBService.getExploitDBFromSite(Long.parseLong(edbID));
    } catch (Exception ignored) {
    }

    if (Objects.isNull(exploitDB)) throw new ExploitUnsupported("Exploit doesn't exist");

    if (!exploitDB.getPlatform().equalsIgnoreCase("PHP"))
      throw new ExploitUnsupported("Platform not supported");

    if (StringUtils.containsIgnoreCase(exploitDB.getTitle(), "wordpress"))
      genConfigurationForWordpress(exploitDB);
  }

  public void genConfigurationForWordpress(@NonNull ExploitDB exploit)
      throws ExploitUnsupported, IOException {
    final var matcherWordpress = PATTERN_WORDPRESS.matcher(exploit.getTitle());

    if (!matcherWordpress.find())
      throw new ExploitUnsupported("Pattern title unknown: " + exploit.getTitle());

    final var exploitDir = new File(BASE_DIR + "/" + exploit.getId());
    if (!exploitDir.exists() && !exploitDir.mkdirs())
      throw new IOException("Impossible to create folder: " + exploitDir.getPath());

    // Extract from title the Type and Target (aka Product)
    var type = WordpressType.valueOf(matcherWordpress.group(1).trim().toUpperCase());
    var target = matcherWordpress.group(2).trim();

    // Extract the version from title
    final var matcher = PATTERN_VERSION_EXPLOITDB.matcher(target);
    if (!matcher.find()) throw new ExploitUnsupported("Pattern version unknown: " + target);

    // Remove the version
    target = Utils.formatString(target.replace(matcher.group(), ""));

    final var less = matcher.group(1);
    final var firstVersion = matcher.group(2);
    final var slash = matcher.group(3);
    final var secondVersion = matcher.group(4);

    String versionWordpress = null;

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
          typeDir = new File(exploitDir, "/plugins/" + target);
          if (!typeDir.exists() && !typeDir.mkdirs())
            throw new IOException("Impossible to create folder: " + typeDir.getPath());
          isCheckout = wordpressService.checkoutPlugin(target, firstVersion, typeDir);
          break;

        case THEME:
          typeDir = new File(exploitDir, "/themes/" + target);
          if (!typeDir.exists() && !typeDir.mkdirs())
            throw new IOException("Impossible to create folder: " + typeDir.getPath());
          isCheckout = wordpressService.checkoutTheme(target, firstVersion, typeDir);
          break;

        default:
          throw new IllegalStateException("Unexpected value: " + type);
      }

      // If checkout has failed and exploit has a vuln app, download and extract it
      if (!isCheckout && exploit.getIdVulnApp() != null) {
        final var zipFile = new File(exploitDir, exploit.getIdVulnApp());
        exploitDBService.downloadVulnApp(exploit.getIdVulnApp(), zipFile);
        extractZip(zipFile, typeDir);
        var files = typeDir.listFiles();
        if (files != null && files.length == 1 && files[0].isDirectory())
          target += "/" + files[0].getName();
      } else if (!isCheckout)
        throw new ExploitUnsupported(type + " not found in SVN and no Vuln App exist");
    }

    // Copy the config files
    copyWordpressContent(exploitDir, type, target, versionWordpress);
  }

  private SearchTagVO.TagVO findTagForWordpress(Version version) throws IOException {
    // Create CPE
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
    }
    return tag;
  }

  private void copyWordpressContent(
      @NonNull File baseDir,
      @NonNull WordpressType type,
      @NonNull String target,
      String wordPressVersion)
      throws IOException {

    FileUtils.copyDirectory(new File(WORDPRESS_DIR), baseDir);
    // Read Docker-compose
    var dockerCompose = new File(baseDir, "docker-compose.yml");
    var dockerContent = readFileToString(dockerCompose, StandardCharsets.UTF_8);

    // Copy the env file and append the plugin or theme name
    var env = new File(baseDir, ".env");
    var contentEnv = readFileToString(env, StandardCharsets.UTF_8);

    switch (type) {
      case CORE:
        contentEnv = contentEnv.replace("latest", wordPressVersion);
        break;
      case PLUGIN:
        contentEnv += "\nPLUGIN_NAME=" + target;
        dockerContent =
            StringUtils.replaceOnce(
                dockerContent,
                "volumes:\n  ",
                "volumes:\n      - ./plugins/${PLUGIN_NAME}/:/var/www/html/wp-content/plugins/${PLUGIN_NAME}\n  ");
        break;
      case THEME:
        contentEnv += "\nTHEME_NAME=" + target;
        dockerContent =
            StringUtils.replaceOnce(
                dockerContent,
                "volumes:\n  ",
                "volumes:\n      - ./themes/${THEME_NAME}/:/var/www/html/wp-content/themes/${THEME_NAME}\n  ");
        break;
    }

    write(env, contentEnv, StandardCharsets.UTF_8);
    write(dockerCompose, dockerContent, StandardCharsets.UTF_8);
  }
}
