# VirusTotal Codeblocks Maltego Transforms

## Introduction
These Maltego transforms allow you to pivot between different PE files based on codeblocks they share in common. 
One transform accepts a hash of a PE file and extracts its codeblocks over a set length threshold; the other transform accepts extracted codeblocks and return hashes of files containing them. This is achieved by using the unique codeblock ID returned from the `code-similar-to:` search modifier and running it with the `code-block:` search modifier in VirusTotal.

For more information, please refer to the Webinar "*Visual investigations - Speed up your IR, Forensic Analysis and Hunting*" at https://www.brighttalk.com/webcast/18282/493986.

## Prerequisites
- VirusTotal Private API key
- Python 2.7.X, requests, json 
- Maltego 4.2.X

## Example
![Codeblocks](/Media/Example.png?raw=true)

**Codeblock properties:**
![Codeblocks properties](/Media/Codeblock_properties.png?raw=true)

## Setup
With the prerequisites met, clone repository to a local folder.

1. Edit both `HashToCodeblocks.py` and `CodeblocksToHash.py` and insert your VirusTotal private API key.
2. Import `VTCodeBlocks.mtz` to Maltego, making sure to import both the transforms and the entity.
3. Go to Transforms -> Transform Manager -> "[VT] Codeblock to Hash" and "[VT] Hash to Codeblock" and set:
  - Command line: `C:\Python27\python.exe` (or your python folder)
  - Working directory: The folder where you cloned this repository to.
  - Uncheck "Show debug info"

## Known issues
Not an issue by itself, but you might get lots of short codeblocks, which might be undesired. You can easily edit the minimal codeblock length inside `HashToCodeblocks.py`:
![Minimal block length](/Media/Block_length.png?raw=true)

