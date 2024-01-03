import os
import yaml

class AtomicParser:
    def __init__(self) -> None:
        supported_platforms = ['windows', 'linux', 'macos']
        
        
        # Grab TTPs
        if 'atomics' in os.listdir('../atomic-red-team'):
            os.chdir('../atomic-red-team/atomics')
        else:
            print("Ensure parser is installed as a sibling folder for atomic red team")


    #ensures proper TTPs are being pulled
    def parse_repo(self):
        ttps_yaml = os.popen(f'find . -name "*.yaml"| grep -vi "src" | grep -vi "Indexes"').read().split()

        return ttps_yaml
    
    def print_test(self, tests, dependencies):
        
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

        print(f"MITRE TECHNIQUE NAME:", tests['display_name'])
        print(f"TECHNIQUE ID:", tests['ttp_code'])
        print(f"Total Number of Tests: {tests['num_of_tests']}")
        print(f"Tests which do require dependencies: {tests['num_with_dependencies']}")
        print(f"Tests which do NOT require dependencies: {tests['num_without_dependencies']}")
        print()
        
        for test in valid_tests:
            print(f"Procedure Name:\n{test['name']}")
            print(f"Description:\n{test['description']}")
            
            if 'dependencies' in test:
                for pre_req in test['dependencies']:
                    print('Dependency Description:', pre_req['description'])
                    print('Dependency Prereq command:', pre_req['prereq_command'])
                
            if ('command' in test['executor']):
                print(f"PAYLOAD:\n{test['executor']['command']}")
            else:
                print("TEST HAS NO PROVIDED COMMANDS/PAYLOADS")
            print()
        

    # parses each individual technique and their tests
    def parse_tests(self, ttp):

        with open(ttp, 'r') as stream:
            
            try:
                contents = yaml.safe_load(stream)
                ttp_code = contents['attack_technique']
                display_name = contents['display_name']

                num_of_tests = len(contents['atomic_tests'])

                tests_with_depends = [test for test in contents['atomic_tests'] if "dependencies" in test]

                tests_without_depends = [test for test in contents['atomic_tests'] if "dependencies" not in test]
                
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
        atomictests.print_test(atomictests.parse_tests(technqiues), True)
