package com.lprevidente.edb2docker;

import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.MOCK,
    classes = Cve2DockerApplication.class,
    properties = "command.line.runner.enabled=false")
class Cve2DockerApplicationTests {

}
