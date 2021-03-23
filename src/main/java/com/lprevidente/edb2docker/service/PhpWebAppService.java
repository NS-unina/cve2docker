package com.lprevidente.edb2docker.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lprevidente.edb2docker.entity.pojo.ExploitDB;
import com.lprevidente.edb2docker.entity.pojo.ExploitType;
import com.lprevidente.edb2docker.entity.pojo.docker.DockerCompose;
import com.lprevidente.edb2docker.exception.*;
import com.lprevidente.edb2docker.utility.ConfigurationUtils;
import com.lprevidente.edb2docker.utility.Utils;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import static com.lprevidente.edb2docker.utility.Utils.*;
import static java.util.regex.Pattern.CASE_INSENSITIVE;
import static java.util.regex.Pattern.compile;
import static org.apache.commons.io.FileUtils.write;
import static org.apache.commons.lang3.StringUtils.containsIgnoreCase;
import static org.apache.commons.lang3.StringUtils.equalsIgnoreCase;

@Service
@Slf4j
public class PhpWebAppService implements IGenerateService {

  @Value("${spring.config.exploits-dir}")
  private String EXPLOITS_DIR;

  @Value("${spring.config.php-webapp.config-dir}")
  private String CONFIG_DIR;

  // To download directly the zip file from sourcecodester
  private static final String PATH_DOWNLOAD_SOURCECODESTER = "/sites/default/files/download";

  private static final Pattern PATTNER_PAGE_SOUCECODESTER =
      Pattern.compile("(?:.*)/([0-9]*)/(.*).html", CASE_INSENSITIVE);

  private static final Pattern PATTERN_DB_NAME = compile("Database:\\s`(.*)`", CASE_INSENSITIVE);

  private static final String[] filenames =
      new String[] {
        "docker-compose.yml", "start.sh", ".env", "config/php/php.ini", "config/vhosts/default.conf"
      };

  private final Long MAX_TIME_TEST;

  public PhpWebAppService(
      @Value("${spring.config.wordpress.max-time-test}") Integer MAX_TIME_TEST) {
    this.MAX_TIME_TEST = TimeUnit.MINUTES.toMillis(MAX_TIME_TEST);
  }

  @Override
  public boolean canHandle(@NonNull ExploitDB exploitDB) {
    return !containsIgnoreCase(exploitDB.getTitle(), ExploitType.JOOMLA.name())
        && !containsIgnoreCase(exploitDB.getTitle(), ExploitType.WORDPRESS.name())
        && equalsIgnoreCase(exploitDB.getPlatform(), ExploitType.PHP.name());
  }

  public void genConfiguration(@NonNull ExploitDB exploit, boolean removeConfig)
      throws GenerationException {
    log.info("Generating configuration for PHP WebApp Exploit");

    String link;
    if (StringUtils.containsIgnoreCase(exploit.getSoftwareLink(), "www.sourcecodester.com")) {
      log.info(
          "Software link related to sourcecodester. Trying to extract the download link for the zip file");
      link = extractDownloadLinkSourcecodester(exploit.getSoftwareLink());
    } else if (StringUtils.containsIgnoreCase(exploit.getSoftwareLink(), "phpgurukul.com")) {
      log.info(
          "Software link related to phpgurukul.  Trying to extract the download link for the zip file");
      link = extractDownloadLinkPhpGuruKul(exploit.getSoftwareLink());
    } else throw new ParseExploitException("Software link unknown " + exploit.getSoftwareLink());

    if (Objects.nonNull(link)) {
      File exploitDir = null;
      try {
        exploitDir = Utils.createDir(EXPLOITS_DIR + "/" + exploit.getId());

        log.info("Downloading the zip file");
        var zipName = link.substring(link.lastIndexOf("/") + 1);
        var dest = new File(exploitDir, zipName);

        copyURLToFile(link, dest);
        var www = new File(exploitDir, "www/");
        if (!www.exists()) www.mkdir();

        decompress(dest, www);
        log.info("Download completed");

        copyContent(exploitDir);
        log.info("Configuration created. Trying to configure it");

        var index =
            FileUtils.listFiles(www, new String[] {"php"}, true).stream()
                .filter(
                    file -> file.getName().equals("index.php") && !file.getPath().contains("admin"))
                .findFirst()
                .orElse(null);

        String endpoint;
        if (Objects.nonNull(index)) {
          endpoint =
              "http://localhost"
                  + StringUtils.remove(index.getCanonicalPath(), www.getCanonicalPath());

          // Activate any plugin/theme and test the configuration
          ConfigurationUtils.setupConfiguration(
              exploitDir, endpoint, MAX_TIME_TEST, removeConfig, (String[]) null);

          cleanDirectory(exploitDir);
          log.info("Container configured correctly! Run container and go to: " + endpoint);
        } else throw new ConfigurationException("No index.php found");
      } catch (IOException e) {
        // In case of error, delete the main directory in order to not leave traces
        if (Objects.nonNull(exploitDir)) {
          try {
            FileUtils.deleteDirectory(exploitDir);
          } catch (IOException ignored) {
          }
        }
        throw new GenerationException("An IO Exception occurred", e);
      }
    } else throw new NoVulnerableAppException();
  }

  private String extractDownloadLinkSourcecodester(String softwareLink) {
    String link = null;
    if (softwareLink.contains(PATH_DOWNLOAD_SOURCECODESTER)) link = softwareLink;
    else {
      var matcher = PATTNER_PAGE_SOUCECODESTER.matcher(softwareLink);

      // Build the download link if the software link is related to sourcecodester
      if (matcher.find()) {
        softwareLink =
            String.format(
                "https://www.sourcecodester.com/download-code?nid=%s&title=%s",
                matcher.group(1), matcher.group(2));
      }

      // Try to extract the download link from download homepage
      try {
        Document doc = Jsoup.parse(new URL(softwareLink), (int) TimeUnit.SECONDS.toMillis(30));
        final var elements = doc.select("a[href]");
        final var href =
            elements.stream()
                .filter(
                    element ->
                        element
                            .attr("href")
                            .contains("https://www.sourcecodester.com/sites/default/files"))
                .findFirst();
        if (href.isPresent()) link = href.get().attr("href");
      } catch (IOException e) {
        log.error(
            "Error extracting the download link form sourcecodester - Software link {} - Error: {}",
            softwareLink,
            e.getMessage());
      }
    }
    return link;
  }

  private String extractDownloadLinkPhpGuruKul(String softwareLink) {
    String link = null;
    try {
      Document doc = Jsoup.parse(new URL(softwareLink), (int) TimeUnit.SECONDS.toMillis(30));
      final var elements = doc.select("a[href]");
      final var href =
          elements.stream()
              .filter(
                  element ->
                      element.attr("href").contains("https://phpgurukul.com/?smd_process_download"))
              .findFirst();
      if (href.isPresent()) link = getLocationMoved(href.get().attr("href"));
    } catch (IOException e) {
      log.error(
          "Error extracting the download link form sourcecodester - Software link {} - Error: {}",
          softwareLink,
          e.getMessage());
    }
    return link;
  }

  private FilenameFilter excludeDS_Store() {
    return (dir, name) -> !name.contains(".DS_Store");
  }

  private File findDump(@NonNull File baseDir) throws StructureFolderException {
    File dump = null;
    var www = new File(baseDir, "www/");
    var files = www.listFiles(excludeDS_Store());

    if (Objects.isNull(files) || files.length == 0)
      throw new StructureFolderException("No project in the www folder");

    if (files.length != 1) // TODO: creare una cartella contenitore?
    throw new StructureFolderException(
          "More than one file in the www folder. There should be only one directory");

    var file = new File(www, Utils.formatString(files[0].getName()));
    files[0].renameTo(file);

    // Get all files inside the directory
    files = file.listFiles(excludeDS_Store());
    if (Objects.isNull(files) || files.length == 0)
      throw new StructureFolderException("No project files inside the directory");

    if (files.length > 2) {
      // Searching for a dump
      var sqls = FileUtils.listFiles(files[0].getParentFile(), new String[] {"sql"}, true);
      if (!sqls.isEmpty()) {
        if (sqls.size() > 1) log.warn("More than one sql file found");
        dump = sqls.iterator().next();
      }
    } else throw new StructureFolderException("Folder structure unknown");
    return dump;
  }

  private void copyContent(@NonNull File baseDir) throws IOException, StructureFolderException {

    ConfigurationUtils.copyFiles(CONFIG_DIR, baseDir, filenames);

    File sql = findDump(baseDir);

    if (Objects.nonNull(sql)) { // IF a dump has been found
      // Copy the env file and append the webapp name
      final var env = new File(baseDir, ".env");
      var contentEnv =
          IOUtils.toString(ConfigurationUtils.getBufferedReaderResource(CONFIG_DIR + "/.env"));

      //  Read Docker-compose
      final var yamlFactory = ConfigurationUtils.getYAMLFactoryDockerCompose();

      ObjectMapper om = new ObjectMapper(yamlFactory);
      final var dockerCompose =
          om.readValue(
              ConfigurationUtils.getBufferedReaderResource(CONFIG_DIR + "/docker-compose.yml"),
              DockerCompose.class);

      dockerCompose
          .getServices()
          .get("db")
          .setVolumes(
              Collections.singletonList(
                  "./config/mysql/${DUMP_NAME}.sql:/docker-entrypoint-initdb.d/dump.sql"));

      // Extract the db name from the sql file
      final var matcher =
          PATTERN_DB_NAME.matcher(FileUtils.readFileToString(sql, StandardCharsets.UTF_8));

      if (matcher.find()) {
        var dbName = matcher.group(1);
        contentEnv += "\nDB_NAME=" + dbName;
        contentEnv += "\nDUMP_NAME=" + FilenameUtils.removeExtension(sql.getName());

        final var confMySQLDir = new File(baseDir, "config/mysql/");
        if (!confMySQLDir.exists() && !confMySQLDir.mkdirs())
          throw new IOException("Impossible to create folder: " + confMySQLDir.getPath());

        FileUtils.moveFileToDirectory(sql, confMySQLDir, false);

        write(env, contentEnv, StandardCharsets.UTF_8);
        om.writeValue(new File(baseDir, "docker-compose.yml"), dockerCompose);
      } else log.warn("No database name found");
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
      FileUtils.forceDelete(new File(exploitDir, "start.sh"));
    } catch (IOException ignored) {
    }
  }
}
