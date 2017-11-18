# Burp-molly-pack

# Overview
Burp-molly-pack is Yandex security checks pack for Burp.
The main goal of Burp-molly-pack is to extend Burp checks.
Plugins contains Active and Passive security checks.

# Usage

* Build fat jar with Maven

`maven build`
* Change and save [burp_molly_config.json](https://github.com/yandex/burp-molly-pack/blob/master/src/main/config/burp_molly_config.json)
* Put path to config in MOLLY_CONFIG Environment variable

`export MOLLY_CONFIG=/path/to/burp_molly_config.json`
* Run Burp Suite in console

`java -jar burpsuite_pro.jar`
* Add Plugins Jar file in Extender Tab

# Contributing
Contributions to Burp-molly-pack are always welcome! You can help us in different ways:
  * Open an issue with suggestions for improvements and errors you're facing;
  * Fork this repository and submit a pull request;
  * Improve the documentation.
