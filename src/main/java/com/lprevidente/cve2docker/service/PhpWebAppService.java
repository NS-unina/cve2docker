package com.lprevidente.cve2docker.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lprevidente.cve2docker.entity.pojo.ExploitDB;
import com.lprevidente.cve2docker.entity.pojo.docker.DockerCompose;
import com.lprevidente.cve2docker.exception.ConfigurationException;
import com.lprevidente.cve2docker.exception.ExploitUnsupported;
import com.lprevidente.cve2docker.utility.ConfigurationUtils;
import com.lprevidente.cve2docker.utility.Utils;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import static com.lprevidente.cve2docker.utility.Utils.copyURLToFile;
import static com.lprevidente.cve2docker.utility.Utils.decompress;
import static java.util.regex.Pattern.CASE_INSENSITIVE;
import static java.util.regex.Pattern.compile;
import static org.apache.commons.io.FileUtils.readFileToString;
import static org.apache.commons.io.FileUtils.write;

@Service
@Slf4j
public class PhpWebAppService {

  @Value("${spring.config.exploits-dir}")
  private String EXPLOITS_DIR;

  @Value("${spring.config.php-webapp.config-dir}")
  private String CONFIG_DIR;

  private final Long MAX_TIME_TEST;

  // To download directly the zip file from sourcecodester
  private static final String PATH_DOWNLOAD_SOURCECODESTER = "/sites/default/files/download";

  private static final Pattern PATTNER_PAGE_SOUCECODESTER =
      Pattern.compile("(?:.*)\\/([0-9]*)\\/(.*).html", CASE_INSENSITIVE);

  private static final Pattern PATTERN_DB_NAME = compile("Database:\\s`(.*)`", CASE_INSENSITIVE);

  public PhpWebAppService(
      @Value("${spring.config.wordpress.max-time-test}") Integer MAX_TIME_TEST) {
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
            ".env",
            "config/php/php.ini",
            "config/vhosts/default.conf"
        };

    for (var filename : filenames) {
      var file = new File(dir, filename);
      if (!file.exists())
        throw new BeanCreationException("No " + file.getName() + " present in " + CONFIG_DIR);
    }
  }

  public void genConfiguration(@NonNull ExploitDB exploit, boolean removeConfig)
      throws IOException, ConfigurationException, ExploitUnsupported {
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
    } else throw new ExploitUnsupported("Software link unknown: " + exploit.getSoftwareLink());

    // TODO: Product HomePage?

    if (Objects.nonNull(link)) {
      final var exploitDir = new File(EXPLOITS_DIR + "/" + exploit.getId());
      if (exploitDir.exists()) FileUtils.deleteDirectory(exploitDir);

      if (!exploitDir.mkdirs())
        throw new IOException("Impossible to create folder: " + exploitDir.getPath());

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

      var endpoint = "";
      if (Objects.nonNull(index)) {
        endpoint =
            "http://localhost"
                + StringUtils.remove(index.getCanonicalPath(), www.getCanonicalPath());

        // Activate any plugin/theme and test the configuration
        ConfigurationUtils.setupConfiguration(
            exploitDir, endpoint, MAX_TIME_TEST, removeConfig, (String[]) null);

        // setupConfiguration(exploitDir, type, product);
        log.info("Container configured correctly! Run container and go to: " + endpoint);

      } else throw new ConfigurationException("No index.php found");

    } else throw new ExploitUnsupported("No source code found for the exploit");
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
      if (href.isPresent()) link = href.get().attr("href");
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

  private File findDump(@NonNull File baseDir) throws ConfigurationException {
    File dump = null;
    var www = new File(baseDir, "www/");
    var files = www.listFiles(excludeDS_Store());

    if (Objects.isNull(files) || files.length == 0)
      throw new ConfigurationException("No project in the www folder");

    if (files.length != 1) // TODO: creare una cartella contenitore?
      throw new ConfigurationException(
          "More than one file in the www folder. There should be only one directory");

    var file = new File(www, Utils.formatString(files[0].getName()));
    files[0].renameTo(file);

    // Get all files inside the directory
    files = file.listFiles(excludeDS_Store());
    if (Objects.isNull(files) || files.length == 0)
      throw new ConfigurationException("No project files inside the directory");

    if (files.length > 2) {
      // Searching for a dump
      var sqls = FileUtils.listFiles(files[0].getParentFile(), new String[] {"sql"}, true);
      if (!sqls.isEmpty()) {
        if (sqls.size() > 1) log.warn("More than one sql file found");
        dump = sqls.iterator().next();
      }
    } else throw new ConfigurationException("Folder structure unknown");
    return dump;
  }

  private void copyContent(@NonNull File baseDir) throws IOException, ConfigurationException {

    FileUtils.copyDirectory(new File(CONFIG_DIR), baseDir);

    File sql = findDump(baseDir);

    if (Objects.nonNull(sql)) { // IF a dump has been found
      // Copy the env file and append the webapp name
      final var env = new File(baseDir, ".env");
      var contentEnv = readFileToString(env, StandardCharsets.UTF_8);

      //  Read Docker-compose
      final var yamlFactory = ConfigurationUtils.getYAMLFactoryDockerCompose();

      ObjectMapper om = new ObjectMapper(yamlFactory);
      final var dockerCompose =
          om.readValue(new File(baseDir, "docker-compose.yml"), DockerCompose.class);

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
        if(!confMySQLDir.exists() && !confMySQLDir.mkdirs())
          throw new IOException("Impossible to create folder: "+confMySQLDir.getPath());

        FileUtils.moveFileToDirectory(sql, confMySQLDir, false);

        write(env, contentEnv, StandardCharsets.UTF_8);
        om.writeValue(new File(baseDir, "docker-compose.yml"), dockerCompose);
      } else log.warn("No database name found");
    }
  }
}
