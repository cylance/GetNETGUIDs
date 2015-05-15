# GetNETGUIDs

A tool to extract GUIDs from .NET assemblies to help identify the projects they belong to.

http://blog.cylance.com/you-me-and-.net-guids

## Help Menu

```
$ getnetguids -h
usage: getnetguids [-h] [-v] [-r] [path [path ...]]

Extracts Typelib IDs and MVIDs from .NET assemblies.

positional arguments:
  path             Paths to files or directories to scan

optional arguments:
  -h, --help       show this help message and exit
  -v, --version    show program's version number and exit
  -r, --recursive  Scan paths recursively

getnetguids v1.2.0 by Brian Wallace (@botnet_hunter)

```