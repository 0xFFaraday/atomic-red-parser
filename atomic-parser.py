import os
import yaml
import re
import csv

class AtomicParser:
    def __init__(self) -> None:
        self.supported_platforms = ['windows', 'linux', 'macos']
        self.current_dir = os.getcwd()
        self.parsed_tests = []
        # Grab TTPs
        if 'atomics' in os.listdir('../atomic-red-team'):
            os.chdir('../atomic-red-team/atomics')
        else:
            print('Ensure parser is installed as a sibling folder for atomic red team')


    #ensures proper TTPs are being pulled
    def parse_repo(self):
        ttps_yaml = os.popen(f'find . -name "*.yaml"| grep -vi "src" | grep -vi "Indexes"').read().split()

        return ttps_yaml
    
    def output_to_csv(self, tests):
        path = self.current_dir + '/output.csv'

        with open(path, 'w+', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(['display_name', 'technique_id', 'payload'])
            
            for test in tests:
                writer.writerow([test['display_name'], test['technique_id'], test['payload']])
            

    def print_test(self, tests, dependencies, regex = False):
        
        # ignores technique if all/none of the tests have dependencies
        if dependencies:
            if tests['num_without_dependencies'] == tests['num_of_tests']:
                return
            else:
                valid_tests = tests['tests_with_depends']
        
        else:
             if tests['num_with_dependencies'] == tests['num_of_tests']:
                return
             else:
                valid_tests = tests['tests_without_depends']

        #search for unique pattern/s in test commands
        if regex:
            download_depenencies = re.compile('https?://')
            matched_tests = []
            for test in valid_tests:
                if ('command' in test['executor'] and re.search(download_depenencies, test["executor"]["command"])):
                    matched_tests.append(test)
            valid_tests = matched_tests
        
        tests_to_output = {
                'display_name':tests['display_name'],
                'technique_id': tests['ttp_code'],
                'payload': None
            }
        
        print(f'MITRE TECHNIQUE NAME:', tests['display_name'])
        print(f'TECHNIQUE ID:', tests['ttp_code'])
        print(f'Total Number of Tests: {tests["num_of_tests"]}')
        print(f'Tests which do require dependencies: {tests["num_with_dependencies"]}')
        print(f'Tests which do NOT require dependencies: {tests["num_without_dependencies"]}')
        print()
        
        for test in valid_tests:
            print(f'Procedure Name:\n{test["name"]}')
            print(f'Description:\n{test["description"]}')
            
            if 'dependencies' in test:
                for pre_req in test['dependencies']:
                    print('Dependency Description:', pre_req['description'])
                    print('Dependency Prereq command:', pre_req['prereq_command'])
                
            if ('command' in test['executor']):
                print(f'PAYLOAD:\n{test["executor"]["command"]}')
                tests_to_output['payload'] = test["executor"]["command"]
            else:
                print('TEST HAS NO PROVIDED COMMANDS/PAYLOADS')
                tests_to_output['payload'] = test["executor"]["command"]
            print()
        
        if len(valid_tests) > 0:
            self.parsed_tests.append(tests_to_output)

    # parses each individual technique and their tests
    def parse_tests(self, ttp):

        with open(ttp, 'r') as stream:
            
            try:
                contents = yaml.safe_load(stream)
                ttp_code = contents['attack_technique']
                display_name = contents['display_name']

                num_of_tests = len(contents['atomic_tests'])

                tests_with_depends = [test for test in contents['atomic_tests'] if 'dependencies' in test]

                tests_without_depends = [test for test in contents['atomic_tests'] if 'dependencies' not in test]
            
                tests_require_dependencies = len(tests_with_depends)

                non_dependencies_tests = len(tests_without_depends)

                return {
                    'display_name': display_name,
                    'ttp_code': ttp_code,
                    'tests_with_depends': tests_with_depends,
                    'tests_without_depends': tests_without_depends,
                    'num_of_tests': num_of_tests,
                    'num_with_dependencies': tests_require_dependencies,
                    'num_without_dependencies': non_dependencies_tests
                }
                
            except yaml.YAMLError as exc:
                print(exc)

if __name__== '__main__':
    atomictests = AtomicParser()

    technqiues = atomictests.parse_repo()

    for technqiue in technqiues:
        # True, True means checks for dependencies and sees if the payload contains the matching regex
        atomictests.print_test(atomictests.parse_tests(technqiue), True)
        
    atomictests.output_to_csv(atomictests.parsed_tests)
