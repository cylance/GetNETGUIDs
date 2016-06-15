# GetNETGUIDs

A tool to extract GUIDs from .NET assemblies to help identify the projects they belong to.

http://blog.cylance.com/you-me-and-.net-guids

## Help Menu

```
$ getnetguids -h
usage: getnetguids [-h] [-v] [-r] [-c] [path [path ...]]

Extracts Typelib IDs and MVIDs from .NET assemblies.

positional arguments:
  path             Paths to files or directories to scan

optional arguments:
  -h, --help       show this help message and exit
  -v, --version    show program's version number and exit
  -r, --recursive  Scan paths recursively
  -c, --csv        Save to CSV

getnetguids v1.4.2 by Brian Wallace (@botnet_hunter)

```
