package com.lprevidente.edb2docker.service;

import com.lprevidente.edb2docker.TestBase;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.io.File;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

public class PhpServiceTest extends TestBase {

  @Value("${spring.config.exploits-dir}")
  private String EXPLOITS_DIR;

  @Autowired private SystemCve2Docker system;

  /** Exploit Php WebApp <b>Source codester</b>: one folder, with inside the sql. */
  @Test
  @Tag("sourceCodester")
  public void testConfigurationOneFolderWithSQL() throws IOException {
    final var edbID = 49493L;
    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    assertDoesNotThrow(() -> system.genConfiguration(edbID, false));
    FileUtils.deleteDirectory(dir);
  }

  /** Exploit Php WebApp <b>Source codester</b>: one folder, with inside a folder containing sql. */
  @Test
  @Tag("sourceCodester")
  public void testConfigurationOneFolderWithSQLInFolder() throws IOException {
    final var edbID = 49471L;
    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    assertDoesNotThrow(() -> system.genConfiguration(edbID, false));
    FileUtils.deleteDirectory(dir);
  }

  /** Exploit Php WebApp <b>Source codester</b>: one folder, with inside a folder containing sql. */
  @Test
  @Tag("sourceCodester")
  public void testLibrarySystem() throws IOException {
    final var edbID = 49434L;
    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    assertDoesNotThrow(() -> system.genConfiguration(edbID, false));
    FileUtils.deleteDirectory(dir);
  }

  /** Exploit Php WebApp <b>Php Gurukul</b>: two folder and a file. Inside one folder there is the sql. */
  @Test
  @Tag("phpGuruKul")
  public void testMonitoringSystem() throws IOException {
    final var edbID = 49503L;
    File dir = new File(EXPLOITS_DIR + "/" + edbID);
    assertDoesNotThrow(() -> system.genConfiguration(edbID, false));
    FileUtils.deleteDirectory(dir);
  }
}
