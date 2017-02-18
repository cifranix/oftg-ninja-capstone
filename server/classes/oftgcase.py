__author__ = 'ryan.ohoro'

import os
import json

class CaseLibrary():
    def __init__(self, path):

        self.path = path
        self.cases = self.enumerate()

    def enumerate(self):
        try:
            cases = {}
            onlyfiles = [f for f in os.listdir(self.path) if os.path.isfile(os.path.join(self.path, f))]
            for fn in onlyfiles:
                if fn[-5:] == '.oftg':
                    cases[fn] = self.parsefile(fn)
            return cases
        except Exception as e:
            print ' ! Failed to load case files'
            raise

    def update(self):
        self.cases = self.enumerate()

    def open(self, casefilename):

        if os.path.isfile(os.path.join(self.path, casefilename)):
            return self.parsefile(os.path.abspath(os.path.join(self.path, casefilename)))
        if os.path.isfile(casefilename):
            return self.parsefile(os.path.abspath(casefilename))

    def parsefile(self, casefilename):
        return json.load(open(os.path.join(self.path, casefilename)))