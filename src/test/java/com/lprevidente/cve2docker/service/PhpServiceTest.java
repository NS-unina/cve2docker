package com.lprevidente.cve2docker.service;

import com.lprevidente.cve2docker.TestBase;
import com.lprevidente.cve2docker.entity.pojo.ExploitDB;
import com.lprevidente.cve2docker.exception.ConfigurationException;
import com.lprevidente.cve2docker.exception.ExploitUnsupported;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.io.File;
import java.io.IOException;

public class PhpServiceTest extends TestBase {

  @Value("${spring.config.exploits-dir}")
  private String EXPLOITS_DIR;

  @Autowired
  private PhpWebAppService service;

  @Autowired
  private SystemCve2Docker system;

  @Test
  public void testConfigurationOneFolderWithSQL() throws IOException, ConfigurationException, ExploitUnsupported {
    final var edbID = "49493";
    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    FileUtils.deleteDirectory(dir);

    var exploit = new ExploitDB();
    exploit.setId(edbID);
    exploit.setSoftwareLink("https://www.sourcecodester.com/sites/default/files/download/oretnom23/onlinegradingsystem.zip");
    service.genConfiguration(exploit, false);
  }

  @Test
  public void testConfigurationOneFolderWithSQLInFolder() throws IOException, ConfigurationException, ExploitUnsupported {
    final var edbID = "49471";
    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    FileUtils.deleteDirectory(dir);

    var exploit = new ExploitDB();
    exploit.setId(edbID);
    exploit.setSoftwareLink("https://www.sourcecodester.com/download-code?nid=12275&title=Library+System+using+PHP%2FMySQli+with+Source+Code");
    service.genConfiguration(exploit, false);
  }

  @Test
  public void testConfigurationTwoFolder() throws IOException, ExploitUnsupported, ConfigurationException {
    final var edbID = 49434L;
    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    FileUtils.deleteDirectory(dir);

    system.genConfigurationFromExploit(edbID, false);
  }
}
