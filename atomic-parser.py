import os
import yaml

#mitre_list = []
# for folder in os.listdir():
#     if folder.startswith('T1'):
#         mitre_list.append(folder)

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
        

    # parses each individual test with specified params 
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
                    #print(ttp_code)
                    #print(f"TESTS WITH DEPENDS:\n{tests_with_depends}")
                    #print()
                    #print(f"TESTS WITHOUT DEPENDS:\n {tests_without_depends}")
                                            
                    # for test in contents['atomic_tests']:
                        
                    #     if counter == 0 and ("dependencies" not in test) != dependencies:
                    #         print(ttp_code,'--' ,display_name)

                    #     if dependencies == False:
                    
                    #         if "dependencies" not in test:
                    #             non_dependencies_tests += 1
                                
                    #             print(f"ATOMIC TEST NAME --", test['name'])
                    #             print(test['description'])
                    #             if ('command' in test['executor']):
                    #                 print(f"PAYLOAD ", test['executor']['command'])
                    #             else:
                    #                 print("TEST HAS NO PROVIDED COMMANDS")
                            
                    #             print('---------------')
                                
                            
                    #     elif dependencies and 'dependencies' in test:
                    #         tests_require_dependencies += 1

                    #         print(f"ATOMIC TEST NAME --", test['name'])
                    #         print(test['description'])
                    #         print()
                            
                    #         if len(test['dependencies']) > 1:
                    #             print("REQUIRES MULTIPLE DEPENDENCIES")
                            
                    #         for pre_req in test['dependencies']:
                    #             print('Dependency Description:', pre_req['description'])
                    #             print('Dependency Prereq command:', pre_req['prereq_command'])
                        
            
                    #         if ('command' in test['executor']):
                    #             print(f"PAYLOAD ", test['executor']['command'])

                    #         else:
                    #                 print("TEST HAS NO PROVIDED COMMANDS")
                            
                            #pre_reqs = dependencies
                    
                            
                            
                    #        print('---------------')

                    #if non_dependencies_tests != 0 and tests_require_dependencies != 0:
                    
                    #print(ttp_code)
                #     print(f"Total Number of Tests: {num_of_tests}")
                #     print(f"Requires Dependencies: {tests_require_dependencies}")
                #     print(f"No Dependencies: {non_dependencies_tests}")
                #     print('---------------')

                # except yaml.YAMLError as exc:
                #     print(exc)

atomictests = AtomicParser()

tests = atomictests.parse_repo()

for test in tests:
     atomictests.print_test(atomictests.parse_tests(test), True)
