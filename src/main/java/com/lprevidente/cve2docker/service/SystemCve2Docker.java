package com.lprevidente.cve2docker.service;

import com.lprevidente.cve2docker.entity.pojo.CPE;
import com.lprevidente.cve2docker.entity.pojo.ExploitDB;
import com.lprevidente.cve2docker.entity.vo.dockerhub.SearchTagVO;
import com.lprevidente.cve2docker.entity.vo.nist.SearchCpeVO;
import com.lprevidente.cve2docker.exception.ExploitUnsupported;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.naming.ConfigurationException;
import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Objects;

@Slf4j
@Service
public class SystemCve2Docker {

  @Autowired private NistService nistService;

  @Autowired private ExploitDBService exploitDBService;

  @Autowired private DockerHubService dockerHubService;

  @Autowired private WordpressService wordpressService;

  @Autowired private JoomlaService joomlaService;

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
      wordpressService.genConfiguration(exploitDB);
    else if (StringUtils.containsIgnoreCase(exploitDB.getTitle(), "joomla"))
      joomlaService.genConfiguration(exploitDB);
  }

  public SearchCpeVO getCpes(CPE cpe) throws IOException {
    return nistService.getCpes(cpe);
  }

  public List<SearchTagVO.TagVO> searchTags(String repoFullName, String text)
      throws IllegalArgumentException {
    return dockerHubService.searchTags(repoFullName, text);
  }

  public void downloadVulnApp(String filenameVulnApp, File destDir) throws IOException {
    exploitDBService.downloadVulnApp(filenameVulnApp, destDir);
  }
}
