# Executing FIWARE Docker Security Scan locally

This is the option when you want to execute locally the scan over some FIWARE GE or over the
complete list of FIWARE GEs.

## Prerequisites

* Docker version 18.09.1 (or newer)
* docker-compose version 1.23.2 (or newer)

## Configuration

The only things that you have to do is download the [container-scan.sh](container-scan.sh) 
file in your local folder to execute the corresponding security scanner over the selected 
FIWARE GE or over the predefined set of FIWARE GEs (see [enablers.json](enablers.json)).

The execution of this script automatically download the following files:
- [docker-compose](docker-compose.yml)
- [default FIWARE GEs](enablers.json)

And it will clone as well the [Docker Bench Security](https://github.com/docker/docker-bench-security) 
folder to make the CIS Docker Benchmark nalyse.

Before launching the script, it is needed to configure the credentials to access to the 
[FIWARE Nexus instance](https://nexus.lab.fiware.org). It will be the place in which we
store the results of the execution of the scan for historical reasons.

## Execution

You can obtain a help description about the execution of the script just executing the 
following command:

```bash
./container-scan.sh -h
```

Which show the following content:

```bash
    Usage: $0 [-pv] [IMAGE_NAME]
    
    Options:
       -p : Pull images before running scan
       -v : Verbose output
       -h : This help message
    
      [IMAGE_NAME] : Optional, Docker image file to be analysed.
                     If it is not provided the Docker images are 
                     obtained from the enablers.json file.
```    

The script will produce 2 files for each FIWARE GE in json format with the format:

```text
<name of ge><date>_<time>.json
``` 

Inside this folder and into the docker-bench-security folder.

Once that we get the files we can get the numbers of security vulnerabilies issues
just executing the following shell commands with the use of the jq program for the
CVE vulnerabilities:

```bash
more <name of ge><date>_<time>.json | jq '.[].vulnerabilities[].severity | select (.=="XXXX")' | wc -l
```

Where XXXX could be Low, Medium, or High values. In case of the CIS Docker Benchmark 
(security best practices) the command that has to be executed is

```bash
more <name of ge><date>_<time>.json | grep YYYY | wc -l
```

Where YYYY could be PASS, INFO, NOTE, or WARN
