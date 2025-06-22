#!/usr/bin/env python3

# read meta/argument_specs.yml
import argparse
import os
import sys

import yaml


def main():
    """Manage default arguments from YAML spec."""
    parser = argparse.ArgumentParser(
        description="Generate default arguments from YAML spec.",
    )
    parser.add_argument("spec_file", type=str, help="Path to the YAML spec file")
    args = parser.parse_args()

    if not os.path.exists(args.spec_file):
        print(f"Error: Spec file '{args.spec_file}' does not exist.")
        sys.exit(1)

    with open(args.spec_file) as file:
        spec = yaml.safe_load(file)

    defaults = spec["argument_specs"]["main"]["options"]
    defaults = dict(sorted(defaults.items()))

    for k, v in defaults.items():
        if v["type"] not in ["dict", "list"]:
            if v["type"] == "bool":
                value_default = str(v["default"]).lower()
            if v["type"] == "int":
                value_default = int(v["default"])
            if v["type"] in ["str", "path"]:
                value_default = f"\"{v['default']}\""

            print(f"\n# {v['description']}\n{k}: {value_default}")

        if v["type"] == "dict":
            print(f"\n# {v['description']}\n{k}:")

            for sv in v["default"]:
                for sk, sv in sorted(sv.items()):
                    if v["options"][sk]["type"] == "bool":
                        subvalue_default = str(sv).lower()
                    elif v["options"][sk]["type"] == "int":
                        subvalue_default = int(sv)
                    elif v["options"][sk]["type"] in ["str", "path"]:
                        subvalue_default = f"\"{sv}\""
                    print(f"  {sk}: {subvalue_default} # {v['options'][sk]['description']}")

        if v["type"] == "list":
            try:
                print(f"\n# {v['description']}\n{k}: {v['default']}")
            except KeyError:
                print(f"\n# {v['description']}\n{k}: []")


if __name__ == "__main__":
    main()
