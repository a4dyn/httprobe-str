# httprobe-strengthen

Take a list of domains and probe for working http and https servers.

## Introduction
This is a customized version. Based on the original httprobe, several more features are added:
* Supports scan IP segment as input
* SUpports scanning specific ports within the IP / IP segment
* Shows the title of the website (if exists)
* Shows the status code of the respose header
* Shows the content length of the respose data (if exists in reposnse header)
* Shows whether the input ports are open

## Original Repo:
```
https://github.com/tomnomnom/hacks
https://github.com/tomnomnom/httprobe	
```

## Basic Usage

httprobe accepts line-delimited domains on `stdin`:
```
echo [IP/IP segment] | ./[httprobe] [variables]
cat [input file] | ./[httprobe] [variables]
./[httprobe] -h
```

### Example Usage
```
echo 8.8.8.8/24 | ./httprobe -p 443,8080 -t 1000
cat domains.txt | ./httprobe -p 8080 -t 500 -s
```

### Output
```
[ip],[url],[title],[status],[content-length],[port open/not]
```

## Others
* If no content-length is found, shows -1
* **Supports Chinese title**（using gbk for windows env, and utf-8 for mac/linux）
* While using -s, by default the ':80' or ':443' will NOT be scanned