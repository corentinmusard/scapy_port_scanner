# scapy_port_scanner

### /!\ Project is not maintained anymore. It contains bugs and undefined behaviours. Use it carefully. /!\

[![MIT license](https://img.shields.io/badge/License-MIT-blue.svg)](https://lbesson.mit-license.org/)
[![HitCount](http://hits.dwyl.io/corentinmusard/scapy_port_scaner.svg)](http://hits.dwyl.io/corentinmusard/scapy_port_scaner)

## Build status
[![Build Status](https://www.travis-ci.org/corentinmusard/scapy_port_scanner.svg?branch=master)](https://www.travis-ci.org/corentinmusard/scapy_port_scanner)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/f078b44da1da4ad4a5bba8dda8fe46c5)](https://www.codacy.com/app/corentinmusard/scapy_port_scanner)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/corentinmusard/scapy_port_scanner/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/corentinmusard/scapy_port_scanner/?branch=master)
[![codecov](https://codecov.io/gh/corentinmusard/scapy_port_scanner/branch/master/graph/badge.svg)](https://codecov.io/gh/corentinmusard/scapy_port_scanner)
[![Maintainability](https://api.codeclimate.com/v1/badges/b115c1a9c3e3328cf07d/maintainability)](https://codeclimate.com/github/corentinmusard/scapy_port_scanner/maintainability)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=corentinmusard_scapy_port_scanner&metric=alert_status)](https://sonarcloud.io/dashboard?id=corentinmusard_scapy_port_scanner)

## Command line options
![help page](https://github.com/corentinmusard/scapy_port_scanner/blob/master/img/help.png "help page")

## Sample Usage
![sample](https://github.com/corentinmusard/scapy_port_scanner/blob/master/img/sample.png "sample")

## Requirements

- python (version >= 3.6)
- venv
- scapy
- nmap

```sh
sudo apt-get install nmap
python -m pip install venv
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pytest -v # Optionnal, it runs tests
```
