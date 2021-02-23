# Cve2Docker (o better *ExploitDB2Docker*)

The project aims is to **automatize** the creation process of docker-compose for an exploit present
in [ExploitDB](https://www.exploit-db.com). Currently *are supported* only exploit related to:

- **WordPress**: Plugin, Theme or Core
- **Joomla**: Component
- **PHP WebApps**

For *WordPress* and **Joomla** there is always the same configuration, that is  ```user/password = test```
, ```project title = test```, ```email = test@test.test```.

For MySQL the root password is simple ```root```.

See **consideration** section for more info.

## Getting Started

### Prerequisites

You need to have:

- **Java** (*11*): the program is built with the framework *Spring Boot* and *Maven*.
- [**Docker**](https://docs.docker.com/engine/)
- [**Docker-compose**](https://docs.docker.com/compose/)

### Usage

There are mainly two ways of usage:

- Generate a configuration for one particular exploit or a list of it, starting from edbid.
  Es ``` java -jar cve2docker.jar --edb-id 12345 ```
- Generate a series of configurations starting from the list of all exploit in ExploitDB and defining different options
  like:
    - *starting date*: date after which the exploit has been published;
    - *end date**:  date before which the exploit has been published;
    - *remove config*: remove the container after it has been tested; doesn't remove the files related to it;
    - *list of exploit types*: WordPress, Joomla or PHP.

  Es. ``` java -jar cve2docker.jar --gen-all --start-date 2020-01-01 --end-date 2020-12-31 --remove-config wordpress ```
  . At the end of this process, the program **generates a CSV** with the result of all configuration.

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
  there is an **official WordPress image** for that version in docker hub, so for versions before 4.0.0 is not possibile
  to proceed.

### PHP WebApps [*Working in progress*]

For the PHP webapps, the automatization process is more complicated. Currently, are supported only the exploit that has:

- a *software link** related to **sourcecodester** or **phpgurukul**.

In most cases, there is a DB dump that must import, so the *system also automatically* find it and import it. *Please
note** the non-automatable step is to *modify the php file to connect to the database*.

