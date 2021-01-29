package com.lprevidente.cve2docker.service;

import com.lprevidente.cve2docker.entity.model.*;
import com.lprevidente.cve2docker.entity.pojo.CPE;
import com.lprevidente.cve2docker.entity.pojo.FilePojo;
import com.lprevidente.cve2docker.entity.pojo.Version;
import com.lprevidente.cve2docker.entity.vo.dockerhub.RepoVO;
import com.lprevidente.cve2docker.entity.vo.dockerhub.SearchRepoVO;
import com.lprevidente.cve2docker.entity.vo.dockerhub.SearchTagVO;
import com.lprevidente.cve2docker.repository.ExplConfigRepository;
import com.lprevidente.cve2docker.utility.Utils;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.tmatesoft.svn.core.SVNException;

import javax.transaction.Transactional;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.*;
import java.util.regex.Pattern;

import static com.lprevidente.cve2docker.utility.Utils.*;
import static org.apache.commons.io.FileUtils.*;
import static org.apache.commons.lang3.StringUtils.*;

@Slf4j
@Service
public class SystemCve2Docker {

  private static final String WORDPRESS_DIR = "./content/wordpress-docker-compose";

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

  @Autowired private GitHubService gitHubService;

  @Autowired private ExplConfigRepository explConfigRepository;

  @Autowired private CVEService cveService;

  @Autowired private WordpressService wordpressService;

  /**
   * Update the database with all information from Exploit DB. <b>At the first time, this operation
   * can more than 7 hours.</b>
   */
  public void updateExploitDB() {
    exploitDBService.update();
  }

  /**
   * Update the database with all information from DockerHub and GitHub. <b>This operation can take
   * several hours.</b>
   */
  @Transactional
  public void updateExploitConfigurations() {
    log.debug("Start update Exploit Configurations");
    long start = System.currentTimeMillis();

    var userGitHubVisited = new ArrayList<String>();
    var configurations = new ArrayList<ExploitConfiguration>();

    try {
      var repos = dockerHubService.searchRepos("cve-");
      repos.forEach(
          repo -> {
            var cveID = cveService.getCveIDFromString(repo.getRepo_name());
            if (isBlank(cveID)) cveID = cveService.getCveIDFromString(repo.getShort_description());

            if (isNotBlank(cveID)) {
              log.info("Found CVE {} in repoName {}", cveID, repo.getRepo_name());
              final var source = dockerHubService.getGitHubSourceRepository(repo.getRepo_name());
              var configurationsFound = new ArrayList<ExploitConfiguration>();

              if (source != null && !userGitHubVisited.contains(source.getOwner())) {
                log.info(
                    "Repo Github found {}/{}. Search exploit configuration files",
                    source.getOwner(),
                    source.getRepository());
                configurationsFound.addAll(
                    gitHubService.findConfigurations(source.getOwner(), source.getRepository()));
                log.info("Exploit Configuration files found: {}", configurationsFound.size());
                userGitHubVisited.add(source.getOwner());
              }

              try {
                int i = repo.getRepo_name().indexOf("/");
                var owner = repo.getRepo_name().substring(0, i);
                var repoName = repo.getRepo_name().substring(i + 1);
                var dockerHubConfig = new DockerHubConfig();

                var cve = cveService.getCVE(cveID);

                dockerHubConfig.setCve(cve);
                dockerHubConfig.setAuthor(owner);
                dockerHubConfig.setRepository(repoName);

                configurationsFound.add(dockerHubConfig);
              } catch (Exception e) {
                log.error("An exception occurred: {}", e.getLocalizedMessage());
                e.printStackTrace();
              }
              configurations.addAll(configurationsFound);
            }
          });
    } catch (Exception e) {
      log.error("An exception occurred: {}", e.getLocalizedMessage());
      e.printStackTrace();
    }
    explConfigRepository.saveAll(configurations);
    log.debug(
        "Finish analyzing in DockerHub. Time spent: {} ms", (System.currentTimeMillis() - start));
  }

  public void genConfigurationFromExploit(@NonNull String edbID) {
    try {
      // Get Information about the Exploit
      final var exploit = exploitDBService.getExploitDBFromSite(Long.parseLong(edbID));
      if (exploit.getType().equalsIgnoreCase("hardware")
          || exploit.getType().equalsIgnoreCase("papers")) return;
      if (exploit.getPlatform().equalsIgnoreCase("PHP")) {
        if (containsIgnoreCase(exploit.getTitle(), "wordpress"))
          genConfigurationForWordpress(exploit);

      } else
        log.error("Unkown exploit platform");

    } catch (ParseException e) {
      log.error("The ID is not a number");
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
  
  public void genConfigurationForPhpWebApps(@NonNull ExploitDB exploitDB) {

  }

  public void genConfigurationForWordpress(@NonNull ExploitDB exploit) throws Exception {
    final var matcherWordpress = PATTERN_WORDPRESS.matcher(exploit.getTitle());
    if (!matcherWordpress.find()) {
      log.error("Impossibile to find the type of wordpress");
      return;
    }

    final var baseDir = new File("./content/" + exploit.getId());
    if (!baseDir.exists()) baseDir.mkdirs();

    var type = matcherWordpress.group(1).trim();
    var target = matcherWordpress.group(2).trim();

    // Extract the version from title
    final var matcher = PATTERN_VERSION_EXPLOITDB.matcher(target);
    if (!matcher.find()) return;

    // remove the version
    target = Utils.formatString(target.replace(matcher.group(), ""));

    final var less = matcher.group(1);
    final var firstVersion = matcher.group(2);
    final var slash = matcher.group(3);
    final var secondVersion = matcher.group(4);

    if (equalsIgnoreCase(type, "core")) {
      log.debug("Exploit {} is wordpress Core", exploit.getId());
      // Copy the config files
      copyWordpressContent(baseDir, "core");

      SearchTagVO.TagVO tag;

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
      } else return;

      if (tag != null) {
        log.debug("Tag found {}", tag.getName());

        // Insert the PLUGIN or THEME name
        var env = new File(baseDir, "/.env");
        var contentEnv = readFileToString(env, StandardCharsets.UTF_8);
        contentEnv =
            contentEnv.replace("WORDPRESS_VERSION=latest", "WORDPRESS_VERSION=" + tag.getName());
        write(env, contentEnv, StandardCharsets.UTF_8);
      }
    } else {
      if (equalsIgnoreCase(type, "plugin")) {
        log.debug("Exploit {} is wordpress PLUGIN", exploit.getId());

        final var pluginDir = new File(baseDir, "/plugin/" + target);
        if (!baseDir.exists()) baseDir.mkdirs();
        try {
          wordpressService.checkoutPlugin(target, firstVersion, pluginDir);
        } catch (SVNException e) {
          log.warn("Plugin in SVN not found");
          if (exploit.getIdVulnApp() != null) {
            final var zipFile = new File(baseDir, "/plugin/" + exploit.getIdVulnApp());
            exploitDBService.downloadVulnApp(exploit.getIdVulnApp(), zipFile);
            extractZip(zipFile, pluginDir);

            var files = pluginDir.listFiles();
            if (files != null && files.length == 1 && files[0].isDirectory())
              target += "/" + files[0].getName();
          }
        }
      } else if (equalsIgnoreCase(type, "theme")) {
        log.debug("Exploit {} is wordpress THEME", exploit.getId());

        final var themeDir = new File(baseDir, "/theme/" + target);
        if (!baseDir.exists()) baseDir.mkdirs();

        try {
          wordpressService.checkoutTheme(target, firstVersion, themeDir);
        } catch (SVNException e) {
          log.warn("Theme {}:{} in SVN not found", target, firstVersion);
          if (exploit.getIdVulnApp() != null) {
            final var zipFile = new File(baseDir, "/theme/" + exploit.getIdVulnApp());
            exploitDBService.downloadVulnApp(exploit.getIdVulnApp(), zipFile);
            extractZip(zipFile, themeDir);
            var files = themeDir.listFiles();
            if (files != null && files.length == 1 && files[0].isDirectory())
              target += "/" + files[0].getName();
          }
        }
      } else return;

      // Copy the config files
      copyWordpressContent(baseDir, type);

      // Insert the PLUGIN or THEME name
      var env = new File(baseDir, "/.env");
      var contentEnv = readFileToString(env, StandardCharsets.UTF_8);
      contentEnv += "\n" + type.toUpperCase() + "_NAME=" + target;
      write(env, contentEnv, StandardCharsets.UTF_8);
    }
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

  private void copyWordpressContent(@NonNull File baseDir, @NonNull String type)
      throws IOException {
    // Copy the env file and appen the plugin or theme name
    copyFile(new File(WORDPRESS_DIR + "/.env"), new File(baseDir, "/.env"));
    // Copy the wordpress docker compose
    copyFile(
        new File(WORDPRESS_DIR + "/docker-compose-" + type + ".yml"),
        new File(baseDir, "/docker-compose.yml"));
    // Copy the config file
    copyDirectory(new File(WORDPRESS_DIR + "/config"), new File(baseDir, "/config"));
  }

  @Transactional
  public List<ExploitConfiguration> getConfigurations(String cveID) {

    log.info("Requested the cveID = {}", cveID);
    final var configurations = new ArrayList<ExploitConfiguration>();
    try {
      var cve = cveService.getCVE(cveID);

      // See if there are already any Exploit Configurations
      configurations.addAll(cve.getConfigurations());

      // Try to generate one
      if (configurations.isEmpty()) {
        configurations.addAll(genConfigurations(cve));
        explConfigRepository.saveAll(configurations);
      }
    } catch (Exception e) {
      log.error("An exception occurred: {}", e.getLocalizedMessage());
      e.printStackTrace();
    }
    return configurations;
  }

  /**
   * Generate a list of configurations (if possible) for the related CVE. The method first searches
   * for at least one exploit related to CVE that it has a vuln app. If it has been found, the
   * second step is to find a repo related to the platform of the exploit, and if so will generate a
   * list of the exploit as many as there are exploits
   *
   * @param cve the CVE object for which want to generate the exploit configurations
   * @return an <i>empty</i> list if no configuration is found
   */
  private List<ExploitConfiguration> genConfigurationFromVulnApp(@NonNull CVE cve) {
    final var configurations = new ArrayList<ExploitConfiguration>();

    // Searching for an exploit with vuln app
    final var exploit =
        (ExploitDB)
            cve.getExploits().stream()
                .filter(
                    _exploit -> {
                      if (_exploit instanceof ExploitDB)
                        return ((ExploitDB) _exploit).getIdVulnApp() != null;
                      return false;
                    })
                .findFirst()
                .orElse(null);

    if (exploit != null) {
      log.debug("Found exploit {} with vulnApp", exploit.getId());
      try {
        // Get Docker image for the platform
        final var repo = dockerHubService.getMostPopularRepo(exploit.getPlatform());

        // Creating the configurations
        if (repo != null) {
          final var urlVulnApp = exploitDBService.getURLVulnApp(exploit.getIdVulnApp());
          configurations.addAll(generateConfigs(cve, repo.getRepo_name(), null, urlVulnApp));
        }
      } catch (Exception e) {
        log.error("An exception occurred: {}", e.getLocalizedMessage());
        e.printStackTrace();
      }
    }
    return configurations;
  }

  /**
   * Generate a list of configurations (if possible) for the related CVE. The method first searches
   * for more information about the CVE, querying the NIST looking for a list of CPE vulnerable. For
   * each CPE of each configuration, the method tries to found a repo image that meets the
   * requirements (also the version). The first image that is found, there will be generated a list
   * of exploit configuration as many as exploits are related to CVE, if there is no one there will
   * be created only one configuration with no information about exploit.
   *
   * @param cve the CVE object for which want to generate the exploit configurations
   * @return an <i>empty</i> list if no configuration is found
   */
  @Transactional
  public List<ExploitConfiguration> genConfigurations(@NonNull CVE cve) {
    List<ExploitConfiguration> configurations = new ArrayList<>();
    try {

      // Get the information about the vulnerability
      final var vulnerabilityVO = nistService.getVulnerability(cve.getId());

      if (vulnerabilityVO == null) { // CVE not found. I cannot continue
        log.warn("No Information about for the CVE");
        return Collections.emptyList();
      }

      // Verify there is at least one configuration to use
      if (vulnerabilityVO.getConfigurations().getNodes().isEmpty()) {
        log.info("No CPE found for the CVE");
        return Collections.emptyList();
      }

      // Search at least one image for all CPE related to CVE
      var iteratorNode = vulnerabilityVO.getConfigurations().getNodes().iterator();
      var mapRepoTags = new HashMap<String, List<SearchTagVO.TagVO>>();
      var mapProductRepo = new HashMap<String, SearchRepoVO.ResultVO>();

      while (iteratorNode.hasNext() && configurations.isEmpty()) {
        var nodeConfigurationVO = iteratorNode.next();

        // TODO: manage the 'AND' operator
        if (nodeConfigurationVO.getOperator().equals("AND")) break;

        var iteratorCPE = nodeConfigurationVO.getCpe_match().iterator();

        while (iteratorCPE.hasNext() && configurations.isEmpty()) {
          var cpeMatchVO = iteratorCPE.next();
          final var cpe = cpeMatchVO.getCpe();

          if (cpe.getPart() == CPE.Part.HARDWARE) {
            log.warn("I'm not capable of creating an exploit with CPE Part as Hardware");
            return Collections.emptyList();
          }

          // If is not a CPE vulnerable go next
          if (!cpeMatchVO.getVulnerable()) continue;

          Version version = null;
          if (cpe.getVersion() != null) version = cpe.getVersion(); // There is a specific version

          if (version == null) continue; // No version found

          log.info(
              "Software {}:{} of {} is vulnerable", cpe.getProduct(), version, cpe.getVendor());

          SearchRepoVO.ResultVO repo;
          if (mapProductRepo.containsKey(cpe.getProduct()))
            repo = mapProductRepo.get(cpe.getProduct());
          else {
            repo = dockerHubService.getMostPopularRepo(cpe.getProduct());
            if (repo == null) break; // No repo found for the product
            mapProductRepo.put(cpe.getProduct(), repo);
          }

          log.info("Found repo {} for product {}", repo.getRepo_name(), cpe.getProduct());

          if (!mapRepoTags.containsKey(repo.getRepo_name()))
            mapRepoTags.put(
                repo.getRepo_name(), dockerHubService.searchTags(repo.getRepo_name(), null));

          if (mapRepoTags.get(repo.getRepo_name()).isEmpty()) continue; // No tag found

          // finding a repo with the exact name of the version
          final var _v = version;
          var tag =
              mapRepoTags.get(repo.getRepo_name()).stream()
                  .filter(_t -> _v.getPattern().matcher(_t.getName()).matches())
                  .findFirst()
                  .orElse(null);

          // If not found, finding the FIRST repo with the containing name of the version
          if (tag == null)
            tag =
                mapRepoTags.get(repo.getRepo_name()).stream()
                    .filter(_t -> _v.getPattern().matcher(_t.getName()).find())
                    .findFirst()
                    .orElse(null);

          // No tag found go next
          if (tag == null) continue;

          log.info("Repo with the tag {} found", tag.getName());

          configurations.addAll(generateConfigs(cve, repo.getRepo_name(), tag.getName(), null));
          // TODO: dove mettere vulnapp
          if (configurations.isEmpty()) {
            var dockerfile = new Dockerfile(repo.getRepo_name(), tag.getName());
            var configuration = new GeneratedConfig(cve, dockerfile);
            configurations.add(configuration);
          }
        }
      }
    } catch (Exception e) {
      log.error("An exception occurred: {}", e.getLocalizedMessage());
      e.printStackTrace();
      return Collections.emptyList();
    }
    return configurations;
  }

  @Transactional
  public List<GeneratedConfig> generateConfigs(
      CVE cve, @NonNull String repoName, String tagName, String urlVulnApp) {
    var configs = new ArrayList<GeneratedConfig>();
    if (isBlank(tagName)) tagName = "latest";

    for (ExploitDefinition _exploit : cve.getExploits()) {
      // TODO: gestire wordpress plugin
      var dockerfile = new Dockerfile(repoName, tagName);
      dockerfile.setUrlExploit(exploitDBService.getURLExploit(Long.parseLong(_exploit.getId())));
      if (isNotBlank(urlVulnApp)) dockerfile.setUrlVulnApp(urlVulnApp);

      var configuration =
          new GeneratedConfig(cve, dockerfile, _exploit.getAuthor(), _exploit.getId());

      configs.add(configuration);
    }
    return configs;
  }

  /**
   * Return the <i>content</i> of docker compose related to the configuration, only if the type is
   * docker-compose.
   *
   * @param config The configuration <b>must</b> contains the url
   * @return <b>null</b> if no file related to url is found.
   * @throws IllegalArgumentException throws when the <i>type of configuration is NOT
   *     docker-compose</i>
   */
  public FilePojo downloadDockerCompose(@NonNull GitHubConfig config)
      throws IllegalArgumentException {
    if (config.getType() != GitHubConfig.Type.DOCKER_COMPOSE)
      throw new IllegalArgumentException(
          "Cannot download docker-compose: type is not DOCKER_COMPOSE");

    FilePojo filePojo = null;
    try {
      final var _file = gitHubService.getContent(config.getRepositoryID(), config.getPath());
      if (isNotBlank(_file.getContent())) {
        filePojo = new FilePojo("docker-compose-core.yml", _file.getContent(), FilePojo.Type.FILE);
      }
    } catch (Exception e) {
      log.error("An exception occurred: {}", e.getLocalizedMessage());
      e.printStackTrace();
    }
    return filePojo;
  }

  /**
   * Return a list of <i>file</i> for the configuration, only if the type is dockerfile. All files
   * inside the same folder of dockerfile will be included.
   *
   * @param config The configuration <b>must</b> contains the url
   * @return <b>null</b> if no file related to url is found.
   * @throws IllegalArgumentException throws when the <i>type of configuration is NOT dockefile</i>
   */
  public List<FilePojo> downloadDockerfile(@NonNull GitHubConfig config)
      throws IllegalArgumentException {
    if (config.getType() != GitHubConfig.Type.DOCKERFILE)
      throw new IllegalArgumentException("Cannot download dockerfile: type is not DOCKERFILE");

    List<FilePojo> filePojos = null;
    try {
      filePojos = gitHubService.getContentsRecursively(config.getRepositoryID(), config.getPath());
    } catch (Exception e) {
      log.error("An exception occurred: {}", e.getLocalizedMessage());
      e.printStackTrace();
    }
    return filePojos;
  }

  /**
   * Return the <i>content</i> of docker compose <i>generated</i> for this configuration, only if
   * the type is IMAGE.
   *
   * @param config The configuration <b>must</b> contains the url
   * @return <b>null</b> if no information about the repo of image found or in case of error.
   * @throws IllegalArgumentException throws when the <i>type of configuration is NOT IMAGE</i>
   */
  public FilePojo genDockerCompose(@NonNull DockerHubConfig config) {
    FilePojo filePojo = null;
    try {
      final var repoVO = dockerHubService.getRepo(config.getAuthor(), config.getRepository());

      if (repoVO == null) {
        log.warn("Repo {}/{} NOT found", config.getAuthor(), config.getRepository());
        return null;
      }

      log.info("Searching a 'docker run' cmd");
      String cmd = searchDockerRunCmdInRepo(repoVO, null);
      var dockerCompose = fromDockerRun2DockerCompose(cmd);

      filePojo =
          new FilePojo(
              "docker-compose-core.yml",
              Base64.getMimeEncoder()
                  .encodeToString(dockerCompose.getBytes(StandardCharsets.UTF_8)),
              FilePojo.Type.FILE);
    } catch (Exception e) {
      log.error("An exception occurred: {}", e.getLocalizedMessage());
      e.printStackTrace();
    }
    return filePojo;
  }

  /**
   * Extract the docker run command in the <i>full description of the repo</i>. If no command is
   * found, it will be used the default command 'docker run repo:tag'.
   *
   * @param repoVO the repo in wich the search should be done
   * @param tag if not specified it wll be used the latest image
   * @return String contaning the command line
   */
  private String searchDockerRunCmdInRepo(@NonNull RepoVO repoVO, String tag) {
    log.info("Searching a 'docker run' cmd in the text");
    String cmd = null;
    if (isNotBlank(repoVO.getFull_description())) {
      var cmds = getDockerRunCmdLine(repoVO.getFull_description());
      if (cmds.length > 0) {
        if (cmds.length > 1) log.warn("Found more than one cmd 'docker run' in description");
        cmd = cmds[0];
      }
    }

    // If no cmd found creating a default one using the latest image of the repo
    if (isBlank(cmd)) {
      log.info("Use of STANDARD command line to run the image");
      cmd = "docker run " + repoVO.getUser() + "/" + repoVO.getName() + ":";
      if (isNotBlank(tag)) cmd += tag;
      else cmd += "latest";
    }
    return cmd;
  }
}
