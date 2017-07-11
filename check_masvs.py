#!/usr/bin/env python3

import os
import os.path


class WorkingDirectory:
    def __init__(self, path):
        self.original_path = os.getcwd()
        self.destination_path = path

    def __enter__(self):
        os.chdir(self.destination_path)
        
    def __exit__(self, type, value, traceback):
        os.chdir(self.original_path)


class MasvsLine:
    pass
        


def parse_arguments():
    import argparse
    parser = argparse.ArgumentParser(description="Check MASVS references")
    parser.add_argument("--masvs-path", help="path to the MASVS repository", default="../owasp-masvs")
    parser.add_argument("--mstg-path", help="path to the MSTG repository", default="../owasp-mstg")
    return parser.parse_args()


def load_module(module_name, module_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def parse_masvs_rules(masvs_path):
    with WorkingDirectory(masvs_path):
        masvs_mod = load_module("masvs", "./masvs.py")
        return masvs_mod.MASVS().requirements


def find_document_files(mstg_path):
    import glob
    return glob.glob(os.path.join(mstg_path, "Document/0x*.md"))


def parse_masvs_line(line):
    import re
    matches = re.match('\s*([-*]+)\s*([Vv]?)((\d)\.(\d+))([: -]+)"(.*)"(.*)$', line)
    if matches is None:
        raise ValueError("Could not parse line '%s'." % line)

    m = MasvsLine()
    (m.bullet, m.v, m.id, m.major, m.minor, m.separator, m.text, m.trail) = matches.groups()
    return m


def find_masvs_in_document(doc_path, masvs_reqs):
    in_masvs = False
    line_number = 0;
    found_lines = []
    out_path = doc_path + ".tmp"
    with open(out_path, "w", newline="\n") as out:
        with open(doc_path, "r", newline="\n") as fp:
            for line in fp:
                line_number += 1

                if line.startswith("##### OWASP MASVS"):
                    in_masvs = True
                elif line.startswith("####"):
                    in_masvs = False
                elif in_masvs and line.strip():
                    try:
                        req = parse_masvs_line(line)
                        req.line_number = line_number
                        req.document_path = doc_path
                        line = fix_requirement_line(masvs_reqs, req)
                    except ValueError as e:
                        print(e)

                out.write(line)
    os.rename(out_path, doc_path)


def find_masvs_requirement(masvs_reqs, doc_req):
    return [m for m in masvs_reqs if m["id"] == doc_req.id][0]


def fix_requirement_line(masvs_reqs, doc_req):
    document = os.path.basename(doc_req.document_path)

    masvs_req = find_masvs_requirement(masvs_reqs, doc_req)
    return '- V%s: "%s"\n' % (masvs_req["id"], masvs_req["text"].strip())
        

if __name__ == "__main__":
    arguments = parse_arguments()
    masvs_reqs = parse_masvs_rules(arguments.masvs_path)
    for doc_path in find_document_files(arguments.mstg_path):
        find_masvs_in_document(doc_path, masvs_reqs)
