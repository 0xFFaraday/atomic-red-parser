# Atomic Red Team Parser

This project serves as a basis to search through all techniques and their associated tests. Depending on your usecase of Atomic Red Team™, you might want to search for specific IOCs that this project provides and potentially does not include currently. This tool will allow you to use custom regex to search across all tests and output to a console/CSV. Bear in mind that the project is in an alpha stage and will continuously be updated with further features.

## Requirements

```shell
git clone https://github.com/redcanaryco/atomic-red-team.git

git clone https://github.com/0xFFaraday/atomic-red-parser.git
```

## Usage

```shell
cd atomic-red-parser && pip install -r requirements.txt

python3 atomic-parser.py
```

### Features

- [x] Extracts which techniques have tests that do/do not have dependencies
- [x] Utilize regex for matching any use case accross all techniques
- [x] Outputs results to CSV for further analysis
- [ ] Add wrapper for further functionality in the command line (Upcoming)