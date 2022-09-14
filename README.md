# ph-xmldsig

Small wrapper around XMLDsig stuff using [Apache Santuario](http://santuario.apache.org/).

# Maven usage

Add the following to your pom.xml to use this artifact, replacing `x.y.z` with the effective version number:

```xml
<dependency>
  <groupId>com.helger</groupId>
  <artifactId>ph-xmldsig</artifactId>
  <version>x.y.z</version>
</dependency>
```

# News and noteworthy

* v5.0.0 - work in progress
    * Using Java 11 as the baseline
    * Updated to ph-commons 11
    * Updated to xmlsec 3.0.0
* v4.4.3 - 2022-08-30
    * Updated to BouncyCastle 1.71 dependencies
    * Updated to ph-commons 10.2.0
    * Updated to xmlsec 2.3.1
* v4.4.2 - 2021-11-19
    * Updated to xmlsec 2.3.0
* v4.4.1 - 2021-09-27
    * Updated to xmlsec 2.2.3
* v4.4.0 - 2021-03-21
    * Updated to ph-commons 10
    * Updated to xmlsec 2.2.1
* v4.3.2 - 2019-06-05
    * Updated to xmlsec 2.2.0
* v4.3.1 - 2019-03-17
    * Updated to xmlsec 2.1.5
* v4.3.0 - 2019-01-15
    * Extended API
    * Renamed `X509KeySelector` to `ContainedX509KeySelector`
* v4.2.0 - 2018-11-22
    * Updated to ph-commons 9.2.0
* v4.1.1 - 2018-07-27
    * Extracted `XMLSignature createXMLSignature` in `XMLDSigCreator` for overloading
* v4.1.0 - 2018-06-20
    * Updated to BouncyCastle 1.59
    * Updated to xmlsec 2.1.2
    * Fixed OSGI ServiceProvider configuration
    * Requires ph-commons 9.1.2 
* v4.0.0 - 2017-11-07
    * Updated to BouncyCastle 1.58
    * Updated to ph-commons 9.0.0
    * Updated to xmlsec 2.1.0
* v3.0.2 - 2016-12-12
    * Updated to xmlsec 2.0.8
    * Updated to BouncyCastle 1.55
* v3.0.1 - 2016-07-15
    * Binds to ph-commons 8.2.x
    * Updated to xmlsec 2.0.7
* v3.0.0 - 2016-06-10
    * Requires now JDK 8
    * Binds to ph-commons 8.x
    * Updated to xmlsec 2.0.6
* v2.0.2 - 2015-10-19   
    * Updated to BouncyCastle 1.53
* v2.0.1 - 2015-07-21
    * Updated to xmlsec 2.0.5
* v2.0.0 - 2015-07-02
    * Binds to ph-commons 6.x     

---

My personal [Coding Styleguide](https://github.com/phax/meta/blob/master/CodingStyleguide.md) |
On Twitter: <a href="https://twitter.com/philiphelger">@philiphelger</a> |
Kindly supported by [YourKit Java Profiler](https://www.yourkit.com)