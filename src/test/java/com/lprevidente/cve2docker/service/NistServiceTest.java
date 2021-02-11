package com.lprevidente.cve2docker.service;

import com.lprevidente.cve2docker.Cve2DockerApplication;
import com.lprevidente.cve2docker.entity.pojo.CPE;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.MOCK,
    classes = Cve2DockerApplication.class)
public class NistServiceTest {

  @Autowired
  private NistService service;

  @Test
  public void getExistingCVE() {
    assertDoesNotThrow(() -> {
      final var vulnerability = service.getVulnerability("2020-1938");
      assertNotNull(vulnerability);
      assertFalse(vulnerability.getCve().getReferences().getReference_data().isEmpty());
      assertNull(vulnerability
          .getCve()
          .getReferences()
          .getReference_data()
          .stream()
          .filter(ref -> ref.getRefsource().equals("EXPLOIT-DB"))
          .findFirst().orElse(null));
      assertFalse(vulnerability.getConfigurations().getNodes().isEmpty());
      CPE.parse("cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*");

      assertTrue(vulnerability.getConfigurations().getNodes().get(0).getCpe_match().stream().anyMatch(cpeMatchVO -> {
        try {
          return cpeMatchVO.getCpe().equals(CPE.parse("cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"));
        } catch (Exception e) {
          e.printStackTrace();
        }
        return false;
      }));
    });
  }

  @Test
  public void getNotExistingCVE() {
    assertDoesNotThrow(() -> {
      final var vulnerability = service.getVulnerability("2018-200001");
      assertNull(vulnerability);
    });
  }
}
