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


def find_masvs_in_document(doc_path):
    in_masvs = False
    line_number = 0;
    found_lines = []
    with open(doc_path, "r") as fp:
        for line in fp:
            line = line.rstrip()
            line_number += 1

            if line.startswith("##### OWASP MASVS"):
                in_masvs = True
            elif line.startswith("####"):
                in_masvs = False
            elif in_masvs and line:
                line = parse_masvs_line(line)
                line.line_number = line_number
                line.document_path = doc_path
                found_lines.append(line)
    return found_lines


def find_masvs_requirement(masvs_reqs, doc_req):
    return [m for m in masvs_reqs if m["id"] == doc_req.id][0]


def check_masvs(masvs_reqs, doc_reqs):
    from fuzzywuzzy import fuzz

    for doc_req in doc_reqs:
        document = os.path.basename(doc_req.document_path)
        try:
            masvs_req = find_masvs_requirement(masvs_reqs, doc_req)
        except:
            # print("MASVS requirement %s not found in %s line %d" % (doc_req.id, document, doc_req.line_number))
            print("- [ ] MASVS V%s in [%s](%s) line %d" % (doc_req.id, document, doc_link, doc_req.line_number))

        if fuzz.ratio(masvs_req["text"], doc_req.text) < 80:
            # print("Requirements text mismatch in %s line %d:" % (document, doc_req.line_number))
            # print("    MASVS: %s" % masvs_req["text"])
            # print("    Doc.:  %s" % doc_req.text)
            masvs_link = "https://github.com/OWASP/owasp-masvs/blob/master/Document/%s" % masvs_req['document']
            doc_link = "https://github.com/OWASP/owasp-mstg/blob/master/Document/%s#owasp-masvs" % document
            print("- [ ] [MASVS V%s](%s) in [%s](%s) line %d" % (doc_req.id, masvs_link, document, doc_link, doc_req.line_number))
            

if __name__ == "__main__":
    arguments = parse_arguments()
    masvs_reqs = parse_masvs_rules(arguments.masvs_path)
    for doc_path in find_document_files(arguments.mstg_path):
        doc_masvs = find_masvs_in_document(doc_path)
        check_masvs(masvs_reqs, doc_masvs)
    

