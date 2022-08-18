# profile_jenkins

This module deploys and configures a Jenkins server.

## Table of Contents

1. [Dependencies](#dependencies)
1. [Usage - Configuration options and additional functionality](#usage)

## Dependencies

- [puppet-jenkins](https://github.com/voxpupuli/puppet-jenkins)
- [puppetlabs-java](https://github.com/puppetlabs/puppetlabs-java)

## Usage

```
include ::profile_jenkins
```

This profile does not manage Java. To use a specific Java version, specify the following in Hiera:

```
java::package: "java-11-openjdk-devel-11.0.16.0.8-1.el8_4.x86_64"
java::java_alternative: "java-11-openjdk.x86_64"
java::java_alternative_path: "/usr/lib/jvm/java-11-openjdk-11.0.16.0.8-1.el8_4.x86_64/bin/java"
```
