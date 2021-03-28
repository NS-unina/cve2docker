package com.lprevidente.edb2docker.service;

import com.lprevidente.edb2docker.TestBase;
import com.lprevidente.edb2docker.entity.pojo.CPE;
import com.lprevidente.edb2docker.entity.pojo.Version;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.junit.jupiter.api.Assertions.*;

@Slf4j
public class NistServiceTest extends TestBase {

  @Autowired
  private NistService service;

  @Test
  public void testCPE() {
    Assertions.assertDoesNotThrow(
        () -> {
          final var cpes =
              service.getCpes(
                  new CPE(
                      "2.3", CPE.Part.APPLICATION, "wordpress", "wordpress", Version.parse("4.8.*")));
          assertNotNull(cpes);
          assertEquals(17, cpes.getTotalResults());
        });
  }

  @Test
  public void testCPEKo() {
    Assertions.assertDoesNotThrow(
        () -> {
          final var cpes =
              service.getCpes(
                  new CPE(
                      "2.5", CPE.Part.APPLICATION, "wordpress", "wordpress", Version.parse("4.8.*")));
          assertNull(cpes);
        });
  }

}
