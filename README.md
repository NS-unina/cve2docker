# Edb2Docker

The project aims is to **automatize** the creation process of docker-compose for an exploit present
in [ExploitDB](https://www.exploit-db.com). Currently *are supported* only exploit related to:

- **WordPress**: Plugin, Theme or Core
- **Joomla**: Component
- **PHP WebApps**

For *WordPress* and **Joomla** there is always the same configuration, that is  ```user/password = test```
, ```project title = test```, ```email = test@test.test```. So the tool takes care of the **initialization of the
project** and also the possible installation of the *plugin*, *theme* or *component* associated with it.

For MySQL the root password is simple ```root```. The access for PhpMyAdmin is `user: root  pass: root`.

See **consideration** section for more info for which exploit is capable of generating.

## Getting Started

### Prerequisites

You need to have:

- **Java** (*11*): the program is built with the framework *Spring Boot* and *Maven*.
- [**Docker**](https://docs.docker.com/engine/)
- [**Docker-compose**](https://docs.docker.com/compose/)

### Generate configuration starting from EdbID

If you are interested in generating a configuration for one particular exploit, you only need the **EdbID**:

```
 java -jar edb2docker.jar -id 12345 
```

You can also generate *multiple configurations* at the same time:

```
 java -jar edb2docker.jar -id 12345 6789 87652
```

If the generation **success**, you can find it in `content/generated/{edbid}`
where you just need to launch the command `docker-compose up`.

### Generate configurations based on criteria

You can also generate a series of configurations based on *different criteria* (no one is mandatory):

``` 
java -jar edb2docker.jar -a -s 2020-01-01 -e 2020-12-31 -r true -t wordpress
```

Where:
```
 -e,--end-date <yyyy-MM-dd>        Date (included) before which the
                                   exploit has been published
 -r,--remove-config <true/false>   If true remove the container after it
                                   has been tested, with the volumes
                                   associated to it. Default: false
 -s,--start-date <yyyy-MM-dd>      Date (included) after which the exploit
                                   has been published
 -t,--type-exploit <type>          [REQUIRED] The exploit types:
                                   wordpress, joomla or php
```
At the end of this process, the program **generates a CSV** with the name `result.csv` with the result of all
configuration.

**Please note** that this command removes *all docker networks* (every 10 configurations) created to free space.

## Consideration

There are some considerations to do for the automation process.

### Joomla

*Not for all exploits* present in exploitDB is possible to create a configuration, *only* for those who meet the
following requirements:

- if related to a **Component/Plugin** has a **vulnerable app** associated with and is compatible wih **Joomla 3.9.x**,
  otherwise if is related to **Core** there is a **official Joomla image** for that version;

### Wordpress

The situation for WordPress is *better* since there is an **official cli** and also an official **SVN** where plugins
and themes are saved. The configuration can be generated *only* for the exploit that meets the following requirements:

- has a **clear distinction** in the title that is related to a PLUGIN, THEME or CORE;
- has a **version written** in the title;
- if is a *plugin/theme* **is present in SVN** (the project and the specific version, since there are some cases where
  the developer has deleted that version) or **has a vulnerable app to download**; instead if is related to *core*,
  there is an **official WordPress image** for that version in docker hub, so for versions before 4.1.0 is not possibile
  to proceed.

### PHP WebApps [*Working in progress*]

For the PHP webapps, the automatization process is more complicated. Currently, are supported only the exploit that has:

- a *software link** related to **sourcecodester** or **phpgurukul**.

In most cases, there is a DB dump that must import, so the *system also automatically* find it and import it. *Please
note** the non-automatable step is to *modify the php file to connect to the database*.

