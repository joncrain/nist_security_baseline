#!/usr/local/bin/python3

import yaml

input_file = "/Users/crain1jp/Projects/macos_security/baselines/all_rules.yaml"

widgets = []

for key, values in yaml.load(open(input_file)).items():
    if key == "profile":
        for value in values:
            for key, value in value.items():
                if key == "rules":
                    widgets += value

n=3
for widget_name in widgets:
    if n % 3 == 0:
      rownum = n//3
      print(f'row{rownum}:')
#     output_file = f'nist_security_baseline_{widget_name}_widget.yml'
#     file = open(output_file, "w")
#     output = f'''type: button
# widget_id: nist_security_baseline-{widget_name}-button-widget
# api_url: /module/nist_security_baseline/get_list/{widget_name}
# i18n_title: nist_security_baseline.widget.{widget_name}_title
# icon: fa-laptop
# listing_link: /show/listing/nist_security_baseline/nist_security_baseline
# buttons:
#   - label: "0"
#     i18n_label: nist_security_baseline.widget.fail
#     class: btn-danger
#   - label: "1"
#     i18n_label: nist_security_baseline.widget.pass
#     class: btn-success
#     '''
#     file.write(output)
#     file.close
    # widget_proper_name = widget_name.replace("_", " ")
    # widget_proper_name = widget_proper_name.title()

    print(f'    nist_security_baseline_{widget_name}: {{  }}')
    n = n +1