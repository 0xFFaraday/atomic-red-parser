import yaml
import platform

with open('../atomic-red-team/atomics/T1027/T1027.yaml', 'r', encoding='utf-8') as file:
       pass
       #print(file.readlines())


with open('../atomic-red-team/atomics/T1027/T1027.yaml', 'r', encoding='utf-8') as stream:
            
            try:
                #print("Attempting to load:", ttp)
                contents = yaml.safe_load(stream)
                ttp_code = contents['attack_technique']
                display_name = contents['display_name']

                print(ttp_code)
                print(display_name)
            except yaml.YAMLError as exc:
                print(exc)

operating_system = platform.platform()

if 'Windows' in operating_system:
    print(operating_system)
