# Atomic Red Team Parser

This project serves as a basis to search through all techniques and their associated tests. Depending on your usecase of Atomic Red Team™, you might want to search for specific IOCs that this project provides and potentially does not include currently. This tool allows the user to use custom regex to search across all tests and output to console & CSV.

### Features

- Extracts which techniques have tests that do/do not have dependencies
- Utilize custom regex for matching any use case accross all techniques
- custom command line arguments for further functionality
- Outputs results to CSV for further analysis

## Requirements

```shell
git clone https://github.com/redcanaryco/atomic-red-team.git

git clone https://github.com/0xFFaraday/atomic-red-parser.git
```

## Usage

```shell
cd atomic-red-parser && pip install -r requirements.txt

python3 atomic-parser.py --help

#Example 1: search for the usage of mimikatz across all tests which do not have declared dependencies
python3 atomic-parser.py --custompattern "mimikatz"

#Example 2: search for the usage of mimikatz across all tests which have declared dependencies
python3 atomic-parser.py --dependencies --custompattern "mimikatz"
```